from gen.messages_pb2 import PgpBlob
from nodes.describe_message_structure import describe_message_structure
from nodes._test_helpers import FakeContext, load_fixture


def test_describe_message_structure_signed_golden():
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob(armored=load_fixture("signed_message.asc")))
    assert result.ok is True
    assert result.is_encrypted is False
    assert result.is_signed is True
    assert result.is_compressed is True
    assert result.compression_algorithm == "ZIP"
    assert result.signature_count == 1
    assert list(result.signature_hash_algorithms) == ["SHA256"]
    assert len(result.pkesk_recipients) == 0
    assert result.skesk_count == 0
    # NOT encrypted, so the literal data envelope is visible (never the raw bytes we didn't ask for)
    assert result.literal_data_present is True
    assert result.literal_data_format == "u"
    assert result.literal_data_length_bytes == 20


def test_describe_message_structure_encrypted_golden():
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob(armored=load_fixture("encrypted_message.asc")))
    assert result.ok is True
    assert result.is_encrypted is True
    assert result.is_signed is False
    assert result.integrity_protected is True
    assert len(result.pkesk_recipients) == 1
    recipient = result.pkesk_recipients[0]
    assert recipient.key_id == "3FF8113EEB0346CC"
    assert recipient.public_key_algorithm == "ECDH"
    assert recipient.version == 3
    assert result.skesk_count == 0
    # encrypted -- literal data envelope must NOT be surfaced (it isn't visible without decrypting)
    assert result.literal_data_present is False
    assert result.literal_data_format == ""
    assert result.literal_data_length_bytes == 0


def test_describe_message_structure_not_a_message_still_parses_generically():
    """DescribeMessageStructure only interprets the packet TYPES it finds; a
    bare key blob has neither PKESK/SEIPD nor a LiteralData packet, so it
    correctly reports is_encrypted=False, is_signed=True (the certification
    signature counts as a Signature packet) and no literal data."""
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.is_encrypted is False
    assert result.is_signed is True
    assert result.signature_count == 2  # the UserID certification + the subkey binding signature
    assert result.literal_data_present is False


def test_describe_message_structure_empty_input_is_error():
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob())
    assert result.ok is False


def test_describe_message_structure_truncation_is_surfaced_not_silent():
    """Mirrors the same truncation-visibility contract as ParsePackets: a
    pathological packet-count blast must not silently undercount
    signature_count/pkesk_recipients/skesk_count."""
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob(binary=b"\x00" * 300_000))
    assert result.ok is True
    assert result.truncated is True


def test_describe_message_structure_normal_input_not_truncated():
    ax = FakeContext()
    result = describe_message_structure(ax, PgpBlob(armored=load_fixture("signed_message.asc")))
    assert result.truncated is False
