from pgpy import PGPSignature
from pgpy.packet import Signature as _RawSignatureRoot

from gen.messages_pb2 import PgpBlob, SignaturePacketResult
from gen.axiom_context import AxiomContext
from nodes._common import (
    PgpParseError,
    enum_name,
    key_flags_names,
    resolve_blob,
    rfc3339,
    subpacket_type_names,
    walk_packets,
)


def parse_signature_packet(ax: AxiomContext, input: PgpBlob) -> SignaturePacketResult:
    """Parse the first Signature packet found in an OpenPGP blob -- a
    standalone/detached .sig file, or the leading signature inside a larger
    key or message -- into its structured fields: signature type, public-key
    and hash algorithm, creation/expiration time, issuer key ID and
    fingerprint, which subpacket types are present in the hashed vs unhashed
    area, and (when present) the KeyFlags and PrimaryUserID subpackets.
    found=false (not an error) when the blob has no Signature packet. This is
    metadata extraction only -- it does NOT cryptographically verify the
    signature.
    """
    try:
        raw, _was_armored, _block_type = resolve_blob(input)
        packets = walk_packets(raw)
    except PgpParseError as e:
        return SignaturePacketResult(ok=False, error=str(e))
    except Exception as e:
        return SignaturePacketResult(ok=False, error=f"failed to parse packet stream: {e}")

    raw_sig = next((p for p in packets if isinstance(p, _RawSignatureRoot)), None)
    if raw_sig is None:
        return SignaturePacketResult(ok=True, found=False)

    try:
        sig = PGPSignature() | raw_sig
    except Exception as e:
        return SignaturePacketResult(ok=False, error=f"failed to interpret signature packet: {e}")

    hashed_types, unhashed_types = subpacket_type_names(raw_sig)

    is_primary_uid = False
    try:
        primary_sps = sig._signature.subpackets["PrimaryUserID"]
        if primary_sps:
            is_primary_uid = bool(next(iter(primary_sps)).primary)
    except Exception:
        pass

    try:
        key_flags = key_flags_names(sig.key_flags)
    except Exception:
        key_flags = []

    expires_at = sig.expires_at

    return SignaturePacketResult(
        ok=True,
        found=True,
        version=int(getattr(raw_sig.header, "version", 0) or 0),
        signature_type=enum_name(sig.type),
        public_key_algorithm=enum_name(sig.key_algorithm),
        hash_algorithm=enum_name(sig.hash_algorithm),
        created=rfc3339(sig.created),
        has_expiration=expires_at is not None,
        expires_at=rfc3339(expires_at),
        issuer_key_id=sig.signer or "",
        issuer_fingerprint=str(sig.signer_fingerprint or ""),
        hashed_subpacket_types=hashed_types,
        unhashed_subpacket_types=unhashed_types,
        is_exportable=bool(sig.exportable),
        is_primary_user_id=is_primary_uid,
        key_flags=key_flags,
    )
