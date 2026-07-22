"""Shared decode/walk/format helpers for every node in this package.

Wraps PGPy (BSD-3-Clause, https://github.com/SecurityInnovation/PGPy) — its
`Armorable` mixin for ASCII-armor encode/decode + CRC24 (RFC 4880 SS6.2/6.3),
its `Packet` dispatcher for generic packet-stream walking (including its own
transparent decompression of CompressedData packets), and its high-level
`PGPKey`/`PGPSignature` wrappers for key and signature metadata. None of the
actual OpenPGP packet framing, MPI/key-material parsing, or signature-field
semantics is reimplemented here — this module supplies only input bounds,
the packet-tag -> name / algorithm-enum -> name formatting glue, and the
generic recursive packet walk.

SCOPE: structural/metadata parsing only. This module (and every node built on
it) never decrypts a message and never signs or cryptographically verifies
anything that would require secret key material. The one verification it does
perform (self-signature checking in ValidateStructure) is a PURE public-key
structural check, identical in kind to checking a self-signed X.509
certificate's own signature — never a trust decision.
"""
import datetime as _datetime

from pgpy import PGPKey, PGPSignature
from pgpy.constants import PacketTag
from pgpy.errors import PGPError
from pgpy.packet import Packet
from pgpy.types import Armorable

# --- Bounds (input -> cost) -------------------------------------------------
# A caller-controlled OpenPGP blob drives parse cost in direct proportion to
# these dimensions. Bounded BEFORE the bytes are handed to the parser.
#
# The Axiom deployed invocation ingress caps request bodies at ~1 MiB; 640 KiB
# keeps every node comfortably under that ceiling. OpenPGP keys/signatures/
# messages are normally tiny (a handful of KiB at most), so this is generous.
MAX_INPUT_BYTES = 640 * 1024

# A safety cap on the FLATTENED packet list a single ParsePackets/
# DescribeMessageStructure call will return, independent of decompression.
# Note this does NOT bound the transient memory a pathological compressed
# packet can make PGPy allocate during decompression itself (PGPy's own
# CompressionAlgorithm.decompress() has no output-size limit) -- that is a
# known, logged limitation of the wrapped library, not something this glue
# code can safely bound without a process-wide side effect that would risk
# starving unrelated concurrent invocations. See the package README.
MAX_PACKETS = 20_000


class PgpParseError(Exception):
    """Raised on malformed input or a bound being exceeded. Every node catches
    this at its boundary and returns a structured (ok=False, error=...) result
    rather than letting an exception escape."""


def _armor_block_type(magic, has_cleartext):
    if has_cleartext:
        return "PGP SIGNED MESSAGE"
    return f"PGP {magic}" if magic else ""


def resolve_blob(blob):
    """Resolve a PgpBlob (binary xor armored) into (raw_bytes, was_armored,
    block_type). Enforces MAX_INPUT_BYTES on the bytes actually handed in,
    before any parsing/dearmoring happens."""
    armored = getattr(blob, "armored", "") or ""
    binary = bytes(getattr(blob, "binary", b"") or b"")

    if armored:
        if len(armored.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
            raise PgpParseError(f"armored input exceeds {MAX_INPUT_BYTES} byte bound")
        try:
            unarmored = Armorable.ascii_unarmor(armored)
        except (ValueError, PGPError) as e:
            raise PgpParseError(f"failed to dearmor input: {e}") from e
        body = bytes(unarmored.get("body") or b"")
        block_type = _armor_block_type(unarmored.get("magic"), unarmored.get("cleartext") is not None)
        return body, True, block_type

    if binary:
        if len(binary) > MAX_INPUT_BYTES:
            raise PgpParseError(f"binary input exceeds {MAX_INPUT_BYTES} byte bound")
        return binary, False, ""

    raise PgpParseError("PgpBlob is empty: provide exactly one of `binary` or `armored`")


def enum_name(value):
    """Best-effort .name for a pgpy constants enum member; falls back to a
    plain string for an opaque/unrecognized underlying value (pgpy leaves the
    raw int in place rather than raising when it meets an algorithm ID it
    doesn't know)."""
    if value is None:
        return ""
    name = getattr(value, "name", None)
    if name:
        return name
    return str(int(value)) if isinstance(value, int) else str(value)


def rfc3339(dt):
    if dt is None:
        return ""
    if isinstance(dt, _datetime.timedelta):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_datetime.timezone.utc)
    return dt.astimezone(_datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_size_and_curve(pgp_key_like):
    """pgpy's `.key_size` is int (bits) for RSA/DSA/ElGamal, an
    EllipticCurveOID for EC/EdDSA/ECDH, and 0 for opaque/unrecognized key
    material. Normalize to (key_size_bits, curve_name)."""
    try:
        size = pgp_key_like.key_size
    except Exception:
        return 0, ""
    if isinstance(size, int):
        return size, ""
    name = getattr(size, "name", None)
    return 0, (name or "")


def key_flags_names(flags):
    try:
        return sorted(f.name for f in (flags or []))
    except Exception:
        return []


def primary_key_flags_names(pgp_key):
    """A PGPKey has no public `.key_flags` property (that name exists only on
    PGPSignature) -- reimplement pgpy's own internal `_get_key_flags` logic
    for a PRIMARY key here rather than reach for that private method: RFC
    4880 requires every primary key be certification-capable, plus whatever
    KeyFlags its first User ID's most recent self-signature declares."""
    try:
        flags = {"Certify"}
        first_uid = next(iter(pgp_key.userids), None)
        if first_uid is not None and first_uid.selfsig is not None:
            flags |= set(key_flags_names(first_uid.selfsig.key_flags))
        return sorted(flags)
    except Exception:
        return []


def subkey_key_flags_names(subkey):
    """Same rationale as primary_key_flags_names, for a SUBKEY: its KeyFlags
    come from its own (most recent) binding signature."""
    try:
        sig = next(iter(subkey.self_signatures), None)
        if sig is None:
            return []
        return key_flags_names(sig.key_flags)
    except Exception:
        return []


# --- Generic packet-stream walk --------------------------------------------

def _packet_tag_name(header):
    try:
        return header.tag.name if hasattr(header.tag, "name") else str(int(header.tag))
    except Exception:
        return "Unknown"


def _packet_tag_number(header):
    try:
        return int(header.tag)
    except Exception:
        return -1


def describe_packet(pkt):
    """Return a brief, type-specific, human-readable detail string for a raw
    pgpy packet object. NEVER includes literal-data content, session-key
    material, or any secret key bytes -- only structural/algorithm metadata."""
    cls = type(pkt).__name__
    try:
        if cls in ("PubKeyV4", "PrivKeyV4", "PubSubKeyV4", "PrivSubKeyV4"):
            algo = enum_name(getattr(pkt, "pkalg", None))
            created = rfc3339(getattr(pkt, "created", None))
            fpr = str(getattr(pkt, "fingerprint", ""))
            keyid = fpr[-16:] if fpr else ""
            kind = "secret" if cls.startswith("Priv") else "public"
            return f"{algo} {kind} key, created {created}, keyid {keyid}"

        if cls == "UserID":
            return f"uid={getattr(pkt, 'uid', '')!s}"

        if cls == "UserAttribute":
            n = len(getattr(pkt, "image", b"") or b"") if hasattr(pkt, "image") else 0
            return f"user attribute ({n} bytes of image subpacket data)" if n else "user attribute"

        if cls == "SignatureV4":
            sigtype = enum_name(getattr(pkt, "sigtype", None))
            pubalg = enum_name(getattr(pkt, "pubalg", None))
            halg = enum_name(getattr(pkt, "halg", None))
            signer = getattr(pkt, "signer", "") or ""
            return f"type={sigtype}, pubalg={pubalg}, hashalg={halg}, issuer={signer}"

        if cls == "OnePassSignatureV3":
            sigtype = enum_name(getattr(pkt, "sigtype", None))
            pubalg = enum_name(getattr(pkt, "pubalg", None))
            signer = getattr(pkt, "signer", "") or ""
            return f"type={sigtype}, pubalg={pubalg}, issuer={signer}"

        if cls == "PKESessionKeyV3":
            pubalg = enum_name(getattr(pkt, "pkalg", None))
            enc = getattr(pkt, "encrypter", "") or ""
            return f"pubalg={pubalg}, recipient_keyid={enc}"

        if cls == "SKESessionKeyV4":
            return "password-based (symmetric-key) session key"

        if cls in ("IntegrityProtectedSKEDataV1",):
            return "integrity-protected (SEIPD)"

        if cls == "SKEData":
            return "legacy unprotected symmetrically-encrypted data (SED)"

        if cls == "CompressedData":
            calg = enum_name(getattr(pkt, "calg", None))
            n = len(getattr(pkt, "packets", []) or [])
            return f"algorithm={calg}, {n} nested packet(s)"

        if cls == "LiteralData":
            fmt = getattr(pkt, "format", "") or ""
            fname = getattr(pkt, "filename", "") or ""
            length = len(getattr(pkt, "_contents", b"") or b"")
            return f"format={fmt}, filename={fname!r}, {length} bytes"

        if cls == "MDC":
            return "modification detection code"

        if cls == "Trust":
            return "trust packet (local keyring metadata)"

        if cls == "Marker":
            return "marker packet (RFC 4880 SS5.8, ignorable)"

        if cls == "Opaque":
            return "unrecognized/opaque packet"

    except Exception:
        return ""

    return ""


def walk_packets(data):
    """Walk a raw OpenPGP packet-stream bytearray into a flat list of
    (index, header, packet) tuples, transparently descending into any
    CompressedData packet's already-decompressed nested packets (pgpy
    decompresses eagerly on parse -- see CompressedData.parse). Bounded to
    MAX_PACKETS total entries; truncated=True is returned if the bound hit."""
    stream = bytearray(data)
    flat = []
    truncated = False

    def _emit(pkt):
        nonlocal truncated
        if len(flat) >= MAX_PACKETS:
            truncated = True
            return
        flat.append(pkt)
        if type(pkt).__name__ == "CompressedData":
            for child in (getattr(pkt, "packets", None) or []):
                if len(flat) >= MAX_PACKETS:
                    truncated = True
                    return
                _emit(child)

    while len(stream) > 0:
        if len(flat) >= MAX_PACKETS:
            truncated = True
            break
        try:
            pkt = Packet(stream)
        except Exception as e:
            raise PgpParseError(f"malformed packet stream: {e}") from e
        _emit(pkt)

    return flat, truncated


# --- Signature subpacket helpers (raw-packet level, used by ParsePackets'
#     nested walk when a Signature packet is found inside a compressed
#     message body, where we don't want the overhead of a full PGPSignature
#     wrap just to build a one-line summary). ---------------------------

def subpacket_type_names(sig_packet):
    """Return (hashed_type_names, unhashed_type_names) for a raw SignatureV4
    packet, reading pgpy's internal SubPackets storage directly -- its public
    MutableMapping API (`.items()`/`.keys()`) is not usable here because
    `SubPackets.__iter__` yields subpacket VALUES, not keys (a pgpy quirk),
    which breaks the mixin-derived `.items()`/`.keys()`."""
    sp = getattr(sig_packet, "subpackets", None)
    if sp is None:
        return [], []
    hashed = sorted({k for k, _ in getattr(sp, "_hashed_sp", {}).keys()})
    unhashed = sorted({k for k, _ in getattr(sp, "_unhashed_sp", {}).keys()})
    return hashed, unhashed
