from pgpy import PGPKey
from pgpy.errors import PGPError
from pgpy.packet import (
    CompressedData as _CompressedData,
    LiteralData as _LiteralData,
    OnePassSignature as _OnePassSignature,
    PKESessionKey as _PKESessionKey,
    Primary as _Primary,
    Private as _Private,
    Public as _Public,
    SKESessionKey as _SKESessionKey,
    Signature as _RawSignatureRoot,
)

from gen.messages_pb2 import PgpBlob, ValidationResult
from gen.axiom_context import AxiomContext
from nodes._common import PgpParseError, enum_name, resolve_blob, walk_packets


def _classify(packets):
    if not packets:
        return "Unknown"
    first = packets[0]
    if isinstance(first, _Primary) and isinstance(first, _Private):
        return "TransferableSecretKey"
    if isinstance(first, _Primary) and isinstance(first, _Public):
        return "TransferablePublicKey"
    if len(packets) == 1 and isinstance(first, _RawSignatureRoot):
        return "DetachedSignature"
    if any(isinstance(p, (_PKESessionKey, _SKESessionKey, _CompressedData, _LiteralData, _OnePassSignature))
           for p in packets):
        return "Message"
    return "Unknown"


def validate_structure(ax: AxiomContext, input: PgpBlob) -> ValidationResult:
    """Validate that an OpenPGP blob's packet sequence is well-formed per RFC
    4880/9580 -- parses end-to-end with no leftover or garbage bytes,
    classifies the object kind, and reports any structural deviations (e.g. a
    subkey with no binding signature). For a key blob, also reports whether
    its self-certification signatures verify against the key's OWN public
    material -- a PURE structural/public-key check, exactly like checking a
    self-signed X.509 certificate -- never a trust decision, and it never
    touches secret key material even when the blob is a secret key.
    """
    try:
        raw, _was_armored, _block_type = resolve_blob(input)
    except PgpParseError as e:
        return ValidationResult(ok=False, error=str(e))

    # RFC 4880 SS4.2: a packet header's first byte always has the high bit
    # (0x80) set. pgpy's own packet parser does not enforce this -- it will
    # cheerfully interpret arbitrary non-PGP bytes as a bogus packet header
    # -- so this package checks it itself to reject obviously-non-OpenPGP
    # input rather than silently misreporting `well_formed: true`.
    if raw and not (raw[0] & 0x80):
        return ValidationResult(
            ok=True, well_formed=False, object_kind="Unknown", packet_count=0,
            structural_issues=["first byte does not have the packet-format high bit (0x80) set -- this is not an OpenPGP packet stream"],
        )

    try:
        packets = walk_packets(raw)
    except PgpParseError as e:
        return ValidationResult(ok=True, well_formed=False, object_kind="Unknown",
                                 structural_issues=[str(e)])
    except Exception as e:
        return ValidationResult(ok=False, error=f"failed to parse packet stream: {e}")

    if not packets:
        return ValidationResult(ok=True, well_formed=False, object_kind="Unknown",
                                 structural_issues=["no OpenPGP packets found in input"])

    object_kind = _classify(packets)
    issues = []

    self_check_applicable = False
    self_sigs_valid = False

    if object_kind in ("TransferablePublicKey", "TransferableSecretKey"):
        self_check_applicable = True
        try:
            key, _ = PGPKey.from_blob(raw)
        except (ValueError, PGPError) as e:
            return ValidationResult(ok=True, well_formed=False, object_kind=object_kind,
                                     structural_issues=[f"key packet sequence rejected by parser: {e}"],
                                     self_signature_check_applicable=True, self_signatures_valid=False)

        for key_id, sub in key.subkeys.items():
            has_binding = any(
                enum_name(getattr(sig, "type", None)) == "Subkey_Binding"
                for sig in sub.self_signatures
            )
            if not has_binding:
                issues.append(f"subkey {key_id} has no binding signature")

        # NOTE: pgpy's own `PGPKey.self_verify()` only checks a DirectlyOnKey
        # signature type, which real-world keys almost never carry (they
        # authenticate via a UserID certification instead) -- it would report
        # NoSelfSignature on nearly every ordinary key. `key.verify(key)`
        # instead verifies every UserID certification and subkey-binding
        # signature this key issued over its own material, which is the
        # check callers actually mean by "does this key's self-signature
        # check out" -- still a pure public-key operation, still no trust
        # decision, still never touching secret material.
        try:
            verification = key.verify(key)
        except Exception as e:
            issues.append(f"self-signature verification raised an error: {e}")
            verification = None

        if verification is None:
            self_sigs_valid = False
        elif len(verification) == 0:
            self_sigs_valid = False
            issues.append("key carries no verifiable self-signature (no UserID certification or subkey binding signed by its own primary key)")
        else:
            self_sigs_valid = bool(verification)
            if not self_sigs_valid:
                issues.append("one or more self-signatures failed to verify")

    return ValidationResult(
        ok=True,
        well_formed=True,
        object_kind=object_kind,
        packet_count=len(packets),
        structural_issues=issues,
        self_signature_check_applicable=self_check_applicable,
        self_signatures_valid=self_sigs_valid,
    )
