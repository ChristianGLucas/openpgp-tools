from pgpy.packet import (
    CompressedData as _CompressedData,
    IntegrityProtectedSKEData as _SEIPD,
    LiteralData as _LiteralData,
    PKESessionKey as _PKESessionKey,
    SKEData as _SEDLegacy,
    SKESessionKey as _SKESessionKey,
    Signature as _RawSignatureRoot,
)

from gen.messages_pb2 import PgpBlob, MessageStructureResult, PkeskRecipient
from gen.axiom_context import AxiomContext
from nodes._common import PgpParseError, enum_name, resolve_blob, rfc3339, walk_packets


def describe_message_structure(ax: AxiomContext, input: PgpBlob) -> MessageStructureResult:
    """Parse an OpenPGP MESSAGE object (encrypted and/or signed and/or
    compressed literal data) into a semantic structural summary: whether it
    is encrypted (with each PKESK recipient's key ID/algorithm, plus a count
    of password-based SKESK packets), whether its encrypted-data packet is
    integrity-protected (SEIPD) or legacy unprotected (SED), whether and how
    it is compressed, whether and how many times it is signed, and -- only
    when the message is NOT encrypted -- the literal data packet's
    format/filename/modification-time/declared length. NEVER decrypts
    anything and NEVER returns literal-data content or any session/secret
    key material.
    """
    try:
        raw, _was_armored, _block_type = resolve_blob(input)
        packets = walk_packets(raw)
    except PgpParseError as e:
        return MessageStructureResult(ok=False, error=str(e))
    except Exception as e:
        return MessageStructureResult(ok=False, error=f"failed to parse packet stream: {e}")

    if not packets:
        return MessageStructureResult(ok=False, error="no OpenPGP packets found in input")

    pkesk_recipients = []
    skesk_count = 0
    integrity_protected = False
    is_encrypted = False
    compression_algorithm = ""
    is_compressed = False
    signature_hash_algorithms = []
    signature_count = 0
    literal = None

    for pkt in packets:
        if isinstance(pkt, _PKESessionKey):
            is_encrypted = True
            pkesk_recipients.append(PkeskRecipient(
                key_id=getattr(pkt, "encrypter", "") or "",
                public_key_algorithm=enum_name(getattr(pkt, "pkalg", None)),
                version=int(getattr(pkt.header, "version", 0) or 0),
            ))
        elif isinstance(pkt, _SKESessionKey):
            is_encrypted = True
            skesk_count += 1
        elif isinstance(pkt, _SEIPD):
            is_encrypted = True
            integrity_protected = True
        elif isinstance(pkt, _SEDLegacy):
            is_encrypted = True
            integrity_protected = False
        elif isinstance(pkt, _CompressedData):
            is_compressed = True
            compression_algorithm = enum_name(getattr(pkt, "calg", None))
        elif isinstance(pkt, _RawSignatureRoot):
            signature_count += 1
            halg = enum_name(getattr(pkt, "halg", None))
            if halg:
                signature_hash_algorithms.append(halg)
        elif isinstance(pkt, _LiteralData):
            literal = pkt

    is_signed = signature_count > 0

    literal_present = literal is not None and not is_encrypted
    result = MessageStructureResult(
        ok=True,
        is_encrypted=is_encrypted,
        is_signed=is_signed,
        is_compressed=is_compressed,
        compression_algorithm=compression_algorithm,
        pkesk_recipients=pkesk_recipients,
        skesk_count=skesk_count,
        integrity_protected=integrity_protected,
        signature_count=signature_count,
        signature_hash_algorithms=signature_hash_algorithms,
        literal_data_present=literal_present,
    )
    if literal_present:
        result.literal_data_format = getattr(literal, "format", "") or ""
        result.literal_data_filename = getattr(literal, "filename", "") or ""
        result.literal_data_modified = rfc3339(getattr(literal, "mtime", None))
        result.literal_data_length_bytes = len(getattr(literal, "_contents", b"") or b"")
    return result
