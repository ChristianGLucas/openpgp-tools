from pgpy.errors import PGPError
from pgpy.types import Armorable

from gen.messages_pb2 import PgpBlob, DearmorResult
from gen.axiom_context import AxiomContext
from nodes._common import MAX_INPUT_BYTES, PgpParseError, _armor_block_type


def dearmor(ax: AxiomContext, input: PgpBlob) -> DearmorResult:
    """Decode ASCII-armored OpenPGP text (a "-----BEGIN PGP ...-----" block,
    as produced by `gpg --armor`) into its raw binary packet stream, per RFC
    4880 SS6.2/6.3. Returns the block type, every armor header line, the
    decoded binary, and the armor's embedded CRC24 checksum both as read and
    as independently recomputed over the decoded data. Malformed armor
    returns a structured error rather than crashing.
    """
    armored = input.armored
    if not armored:
        return DearmorResult(ok=False, error="PgpBlob.armored must be set (Dearmor takes ASCII-armored text; already-binary input needs no dearmoring)")

    if len(armored.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return DearmorResult(ok=False, error=f"armored input exceeds {MAX_INPUT_BYTES} byte bound")

    try:
        unarmored = Armorable.ascii_unarmor(armored)
    except (ValueError, PGPError) as e:
        return DearmorResult(ok=False, error=f"failed to dearmor input: {e}")
    except Exception as e:
        return DearmorResult(ok=False, error=f"failed to dearmor input: {e}")

    body = bytes(unarmored.get("body") or b"")
    magic = unarmored.get("magic")
    has_cleartext = unarmored.get("cleartext") is not None
    block_type = _armor_block_type(magic, has_cleartext)

    if not block_type:
        return DearmorResult(ok=False, error="input is not a recognizable ASCII-armored OpenPGP block")

    headers = dict(unarmored.get("headers") or {})

    crc_read = unarmored.get("crc")
    crc_computed = Armorable.crc24(bytearray(body))
    crc_hex = f"{crc_read:06X}" if crc_read is not None else ""
    crc_valid = (crc_read is not None) and (crc_read == crc_computed)

    return DearmorResult(
        ok=True,
        block_type=block_type,
        data=body,
        headers=headers,
        crc24_hex=crc_hex,
        crc24_valid=crc_valid,
    )
