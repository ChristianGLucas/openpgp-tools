from gen.messages_pb2 import PgpBlob
from nodes.parse_signature_packet import parse_signature_packet
from nodes._test_helpers import FakeContext, load_fixture


def test_parse_signature_packet_detached_golden():
    ax = FakeContext()
    result = parse_signature_packet(ax, PgpBlob(armored=load_fixture("detached_signature.asc")))
    assert result.ok is True
    assert result.found is True
    assert result.version == 4
    assert result.signature_type == "BinaryDocument"
    assert result.public_key_algorithm == "EdDSA"
    assert result.hash_algorithm == "SHA256"
    assert result.issuer_key_id == "55DA1BBB319A8C63"
    assert result.issuer_fingerprint == "C389CFB6FF51421B2EBAA3C455DA1BBB319A8C63"
    assert result.is_exportable is True
    assert result.is_primary_user_id is False
    assert "CreationTime" in result.hashed_subpacket_types
    assert "IssuerFingerprint" in result.hashed_subpacket_types
    assert "Issuer" in result.unhashed_subpacket_types


def test_parse_signature_packet_key_certification():
    """The leading self-certification signature embedded in the pubkey
    fixture -- a Positive Certification over the User ID, carrying KeyFlags
    and PrimaryUserID subpackets that the detached signature does not."""
    ax = FakeContext()
    result = parse_signature_packet(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.found is True
    assert result.signature_type == "Positive_Cert"
    assert set(result.key_flags) == {"Certify", "Sign"}


def test_parse_signature_packet_not_found_is_not_an_error():
    ax = FakeContext()
    result = parse_signature_packet(ax, PgpBlob(armored=load_fixture("encrypted_message.asc")))
    assert result.ok is True
    assert result.found is False


def test_parse_signature_packet_empty_input_is_error():
    ax = FakeContext()
    result = parse_signature_packet(ax, PgpBlob())
    assert result.ok is False
