from gen.messages_pb2 import PgpBlob
from nodes._common import MAX_INPUT_BYTES
from nodes.parse_packets import parse_packets
from nodes._test_helpers import FakeContext, load_fixture


def test_parse_packets_pubkey_golden():
    ax = FakeContext()
    result = parse_packets(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.was_armored is True
    assert result.armor_block_type == "PGP PUBLIC KEY BLOCK"
    assert result.truncated is False

    tags = [p.tag_name for p in result.packets]
    assert tags == ["PublicKey", "UserID", "Signature", "PublicSubKey", "Signature"]

    pubkey_pkt = result.packets[0]
    assert pubkey_pkt.tag_number == 6
    assert pubkey_pkt.new_format is True
    assert pubkey_pkt.body_length_bytes == 51
    assert "EdDSA" in pubkey_pkt.detail
    assert "55DA1BBB319A8C63" in pubkey_pkt.detail

    uid_pkt = result.packets[1]
    assert "fixture@example.test" in uid_pkt.detail

    cert_sig = result.packets[2]
    assert "Positive_Cert" in cert_sig.detail

    binding_sig = result.packets[4]
    assert "Subkey_Binding" in binding_sig.detail


def test_parse_packets_compressed_signed_message_descends_into_compression():
    """The signed_message fixture is a CompressedData packet at the top level
    (pgpy compresses One-Pass-Signature+LiteralData+Signature together) --
    ParsePackets must transparently descend into it, since pgpy decompresses
    eagerly on parse."""
    ax = FakeContext()
    result = parse_packets(ax, PgpBlob(armored=load_fixture("signed_message.asc")))
    assert result.ok is True
    tags = [p.tag_name for p in result.packets]
    assert tags == ["CompressedData", "OnePassSignature", "LiteralData", "Signature"]
    assert "ZIP" in result.packets[0].detail


def test_parse_packets_encrypted_message():
    ax = FakeContext()
    result = parse_packets(ax, PgpBlob(armored=load_fixture("encrypted_message.asc")))
    assert result.ok is True
    tags = [p.tag_name for p in result.packets]
    assert tags == ["PublicKeyEncryptedSessionKey", "SymmetricallyEncryptedIntegrityProtectedData"]
    # never exposes the encrypted plaintext ("secret payload", see fixture generation) or key material
    for p in result.packets:
        assert "secret payload" not in p.detail


def test_parse_packets_binary_input():
    ax = FakeContext()
    from nodes.dearmor import dearmor
    d = dearmor(ax, PgpBlob(armored=load_fixture("detached_signature.asc")))
    result = parse_packets(ax, PgpBlob(binary=bytes(d.data)))
    assert result.ok is True
    assert result.was_armored is False
    assert result.armor_block_type == ""
    assert len(result.packets) == 1
    assert result.packets[0].tag_name == "Signature"


def test_parse_packets_empty_input_is_error():
    ax = FakeContext()
    result = parse_packets(ax, PgpBlob())
    assert result.ok is False
    assert result.error != ""


def test_parse_packets_oversized_input_is_error():
    ax = FakeContext()
    result = parse_packets(ax, PgpBlob(binary=b"\x00" * (MAX_INPUT_BYTES + 1024)))
    assert result.ok is False


def test_parse_packets_truncation_is_surfaced_not_silent():
    """A pathological stream of tiny all-zero "packets" (each a valid
    2-byte old-format header: tag 0 / Invalid, 0-length body) exceeds the
    20,000-packet bound well within the MAX_INPUT_BYTES input cap. The node
    must say so via `truncated=true` rather than silently returning a
    partial list that looks complete."""
    ax = FakeContext()
    # 300,000 bytes of zeros = 150,000 two-byte "packets" -- far over the bound.
    result = parse_packets(ax, PgpBlob(binary=b"\x00" * 300_000))
    assert result.ok is True
    assert result.truncated is True
    assert len(result.packets) == 20_000
