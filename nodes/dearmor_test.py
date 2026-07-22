from gen.messages_pb2 import PgpBlob, DearmorResult
from nodes.dearmor import dearmor
from nodes._test_helpers import FakeContext, crc24_independent, load_fixture


def test_dearmor_pubkey_golden():
    ax = FakeContext()
    result = dearmor(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.block_type == "PGP PUBLIC KEY BLOCK"
    assert len(result.data) == 428
    # new-format packet header, tag 6 (PublicKey): 0xC6, 1-byte length 51
    assert result.data[0] == 0xC6
    assert result.data[1] == 51
    assert result.crc24_valid is True


def test_dearmor_crc24_independent_oracle():
    """The CRC24 validity check is cross-checked against a from-scratch
    RFC 4880 SS6.1 implementation (nodes/_test_helpers.crc24_independent),
    independent of pgpy.types.Armorable.crc24 which the node itself uses."""
    ax = FakeContext()
    result = dearmor(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    oracle_crc = crc24_independent(bytes(result.data))
    assert result.crc24_hex == f"{oracle_crc:06X}"
    assert result.crc24_valid is True


def test_dearmor_detached_signature():
    ax = FakeContext()
    result = dearmor(ax, PgpBlob(armored=load_fixture("detached_signature.asc")))
    assert result.ok is True
    assert result.block_type == "PGP SIGNATURE"
    assert result.crc24_valid is True


def test_dearmor_missing_armored_field_is_error():
    ax = FakeContext()
    result = dearmor(ax, PgpBlob(binary=b"\x01\x02\x03"))
    assert result.ok is False
    assert "armored" in result.error.lower()


def test_dearmor_malformed_armor_returns_structured_error():
    ax = FakeContext()
    result = dearmor(ax, PgpBlob(armored="-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot valid base64!!!\n-----END PGP PUBLIC KEY BLOCK-----\n"))
    assert isinstance(result, DearmorResult)
    assert result.ok is False
    assert result.error != ""


def test_dearmor_empty_input_is_error():
    ax = FakeContext()
    result = dearmor(ax, PgpBlob())
    assert result.ok is False
