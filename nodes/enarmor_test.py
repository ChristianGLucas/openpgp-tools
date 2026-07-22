from gen.messages_pb2 import PgpBlob, EnarmorInput, ArmorHeader
from nodes.dearmor import dearmor
from nodes.enarmor import enarmor
from nodes._test_helpers import FakeContext, crc24_independent, load_fixture


def test_enarmor_golden():
    ax = FakeContext()
    dearmored = dearmor(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert dearmored.ok is True

    result = enarmor(ax, EnarmorInput(data=bytes(dearmored.data), block_type="PUBLIC KEY BLOCK"))
    assert result.ok is True
    assert result.armored.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
    assert result.armored.rstrip().endswith("-----END PGP PUBLIC KEY BLOCK-----")
    assert result.crc24_hex == dearmored.crc24_hex


def test_enarmor_crc24_independent_oracle():
    ax = FakeContext()
    dearmored = dearmor(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    result = enarmor(ax, EnarmorInput(data=bytes(dearmored.data), block_type="public key block"))
    oracle = crc24_independent(bytes(dearmored.data))
    assert result.crc24_hex == f"{oracle:06X}"


def test_enarmor_dearmor_round_trip():
    """Enarmor(Dearmor(x)) reproduces the original binary byte-for-byte, and
    re-dearmoring the re-armored text recovers the exact same bytes."""
    ax = FakeContext()
    original_armored = load_fixture("signed_message.asc")
    step1 = dearmor(ax, PgpBlob(armored=original_armored))
    assert step1.ok is True

    step2 = enarmor(ax, EnarmorInput(data=bytes(step1.data), block_type="MESSAGE"))
    assert step2.ok is True

    step3 = dearmor(ax, PgpBlob(armored=step2.armored))
    assert step3.ok is True
    assert bytes(step3.data) == bytes(step1.data)
    assert step3.crc24_hex == step1.crc24_hex


def test_enarmor_with_custom_header():
    ax = FakeContext()
    result = enarmor(ax, EnarmorInput(
        data=b"\x01\x02\x03\x04",
        block_type="MESSAGE",
        headers=[ArmorHeader(key="Comment", value="hello world")],
    ))
    assert result.ok is True
    assert "Comment: hello world" in result.armored
    assert "Version:" in result.armored


def test_enarmor_empty_data_is_error():
    ax = FakeContext()
    result = enarmor(ax, EnarmorInput(data=b"", block_type="MESSAGE"))
    assert result.ok is False


def test_enarmor_invalid_block_type_is_error():
    ax = FakeContext()
    result = enarmor(ax, EnarmorInput(data=b"\x01\x02", block_type="NOT A REAL TYPE"))
    assert result.ok is False
    assert "block_type" in result.error


def test_enarmor_oversized_input_is_error():
    ax = FakeContext()
    result = enarmor(ax, EnarmorInput(data=b"\x00" * (700 * 1024), block_type="MESSAGE"))
    assert result.ok is False
