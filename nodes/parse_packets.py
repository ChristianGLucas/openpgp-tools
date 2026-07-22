from gen.messages_pb2 import PgpBlob, PacketListResult, PacketSummary
from gen.axiom_context import AxiomContext
from nodes._common import (
    PgpParseError,
    describe_packet,
    resolve_blob,
    walk_packets,
)


def parse_packets(ax: AxiomContext, input: PgpBlob) -> PacketListResult:
    """Walk an OpenPGP blob (ASCII-armored or binary) packet-by-packet and
    return its full structural decomposition -- for each packet, its
    position, RFC packet tag, header format, declared body length, and a
    brief type-specific detail string (algorithm, key/issuer ID, signature
    type, literal-data filename -- never literal-data content or any secret
    material). Works on ANY OpenPGP object -- a key, a detached signature, or
    a message. Transparently descends into compressed-data packets (pgpy
    decompresses them on parse) so a compressed signed message still shows
    its One-Pass-Signature/Literal-Data/Signature layers. Malformed input
    returns a structured error rather than crashing.
    """
    try:
        raw, was_armored, block_type = resolve_blob(input)
        packets, truncated = walk_packets(raw)
    except PgpParseError as e:
        return PacketListResult(ok=False, error=str(e))
    except Exception as e:
        return PacketListResult(ok=False, error=f"failed to parse packet stream: {e}")

    if not packets:
        return PacketListResult(ok=False, error="no OpenPGP packets found in input")

    summaries = []
    for i, pkt in enumerate(packets):
        header = pkt.header
        summaries.append(PacketSummary(
            index=i,
            tag_name=(header.tag.name if hasattr(header.tag, "name") else str(int(header.tag))),
            tag_number=int(header.tag),
            new_format=bool(getattr(header, "_lenfmt", 1)),
            body_length_bytes=int(getattr(header, "length", 0) or 0),
            detail=describe_packet(pkt),
        ))

    result = PacketListResult(
        ok=True,
        was_armored=was_armored,
        armor_block_type=block_type,
        packets=summaries,
    )
    if truncated:
        ax.log.warn(f"ParsePackets: packet list truncated at bound for input of {len(raw)} bytes")
    return result
