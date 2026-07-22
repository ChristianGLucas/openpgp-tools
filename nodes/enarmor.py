import base64

from pgpy.types import Armorable

from gen.messages_pb2 import EnarmorInput, ArmoredResult
from gen.axiom_context import AxiomContext
from nodes._common import MAX_INPUT_BYTES

_VALID_BLOCK_TYPES = {
    "PUBLIC KEY BLOCK",
    "PRIVATE KEY BLOCK",
    "MESSAGE",
    "SIGNATURE",
}


def _normalize_block_type(raw):
    t = (raw or "").strip().upper()
    if t.startswith("PGP "):
        t = t[4:].strip()
    t = t.strip("- ")
    return t


def enarmor(ax: AxiomContext, input: EnarmorInput) -> ArmoredResult:
    """Encode raw OpenPGP binary packet data into ASCII armor, per RFC 4880
    SS6.2/6.3 -- wraps the base64 body in "-----BEGIN PGP <block_type>-----" /
    "-----END PGP <block_type>-----" delimiters, computes and appends the
    CRC24 checksum line, and includes any caller-supplied header lines
    alongside an automatically-added Version header. Round-trips byte-for-byte
    with Dearmor. block_type is one of PUBLIC KEY BLOCK, PRIVATE KEY BLOCK,
    MESSAGE, or SIGNATURE (case-insensitive).
    """
    data = bytes(input.data or b"")
    if not data:
        return ArmoredResult(ok=False, error="EnarmorInput.data must not be empty")
    if len(data) > MAX_INPUT_BYTES:
        return ArmoredResult(ok=False, error=f"input exceeds {MAX_INPUT_BYTES} byte bound")

    block_type = _normalize_block_type(input.block_type)
    if block_type not in _VALID_BLOCK_TYPES:
        return ArmoredResult(
            ok=False,
            error=f"block_type must be one of {sorted(_VALID_BLOCK_TYPES)}, got {input.block_type!r}",
        )

    header_lines = ["Version: christiangeorgelucas/openpgp-tools"]
    for h in input.headers:
        key = (h.key or "").strip()
        if not key or key == "Version":
            continue
        # header values must not contain a newline (would break framing)
        value = (h.value or "").replace("\r", "").replace("\n", " ")
        header_lines.append(f"{key}: {value}")

    b64 = base64.b64encode(data).decode("ascii")
    body_lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]

    crc = Armorable.crc24(bytearray(data))
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")

    parts = [f"-----BEGIN PGP {block_type}-----"]
    parts.extend(header_lines)
    parts.append("")
    parts.extend(body_lines)
    parts.append(f"={crc_b64}")
    parts.append(f"-----END PGP {block_type}-----")
    armored = "\n".join(parts) + "\n"

    return ArmoredResult(ok=True, armored=armored, crc24_hex=f"{crc:06X}")
