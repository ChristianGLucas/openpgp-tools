from gen.messages_pb2 import PgpBlob
from nodes.validate_structure import validate_structure
from nodes._test_helpers import FakeContext, load_fixture


def test_validate_structure_pubkey_golden():
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.well_formed is True
    assert result.object_kind == "TransferablePublicKey"
    assert result.packet_count == 5
    assert result.self_signature_check_applicable is True
    assert result.self_signatures_valid is True
    assert list(result.structural_issues) == []


def test_validate_structure_secret_key():
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob(armored=load_fixture("seckey.asc")))
    assert result.ok is True
    assert result.object_kind == "TransferableSecretKey"
    assert result.self_signature_check_applicable is True
    assert result.self_signatures_valid is True


def test_validate_structure_detached_signature():
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob(armored=load_fixture("detached_signature.asc")))
    assert result.ok is True
    assert result.well_formed is True
    assert result.object_kind == "DetachedSignature"
    assert result.self_signature_check_applicable is False


def test_validate_structure_message():
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob(armored=load_fixture("signed_message.asc")))
    assert result.ok is True
    assert result.object_kind == "Message"
    assert result.self_signature_check_applicable is False


def test_validate_structure_non_pgp_bytes_not_well_formed():
    """RFC 4880 SS4.2: a packet header's first byte always has the high bit
    set. pgpy itself does not enforce this and would happily "parse" such
    bytes; this package checks it directly so obviously-non-PGP input is
    correctly reported, not silently misclassified as well-formed."""
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob(binary=b"not a pgp packet stream at all"))
    assert result.ok is True
    assert result.well_formed is False
    assert result.object_kind == "Unknown"
    assert len(result.structural_issues) > 0


def test_validate_structure_empty_input_is_error():
    ax = FakeContext()
    result = validate_structure(ax, PgpBlob())
    assert result.ok is False
