from gen.messages_pb2 import PgpBlob
from nodes.extract_key_metadata import extract_key_metadata
from nodes.dearmor import dearmor
from nodes._test_helpers import FakeContext, load_fixture, v4_fingerprint_independent


def test_extract_key_metadata_pubkey_golden():
    ax = FakeContext()
    result = extract_key_metadata(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.ok is True
    assert result.is_secret is False
    assert result.fingerprint == "C389CFB6FF51421B2EBAA3C455DA1BBB319A8C63"
    assert result.key_id == "55DA1BBB319A8C63"
    assert result.key_algorithm == "EdDSA"
    assert result.curve == "Ed25519"
    assert result.created == "2024-01-15T12:00:00Z"
    assert result.has_expiration is False
    assert result.expires_at == ""
    assert set(result.key_flags) == {"Certify", "Sign"}

    assert len(result.user_ids) == 1
    uid = result.user_ids[0]
    assert uid.name == "Test Fixture"
    assert uid.comment == "openpgp-tools fixture"
    assert uid.email == "fixture@example.test"
    assert uid.uid == "Test Fixture (openpgp-tools fixture) <fixture@example.test>"

    assert len(result.subkeys) == 1
    sub = result.subkeys[0]
    assert sub.key_id == "3FF8113EEB0346CC"
    assert sub.key_algorithm == "ECDH"
    assert sub.curve == "Curve25519"
    assert sub.binding_signature_present is True
    assert sub.revoked is False
    assert set(sub.key_flags) == {"EncryptCommunications", "EncryptStorage"}


def test_extract_key_metadata_secret_key_never_leaks_secret_material():
    """is_secret must be True for a Transferable Secret Key, but every OTHER
    field (fingerprint, algorithm, uids) must be identical to the public key
    -- and the message schema must not carry any field for secret key bytes."""
    ax = FakeContext()
    pub_result = extract_key_metadata(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    sec_result = extract_key_metadata(ax, PgpBlob(armored=load_fixture("seckey.asc")))

    assert sec_result.ok is True
    assert sec_result.is_secret is True
    assert pub_result.is_secret is False
    assert sec_result.fingerprint == pub_result.fingerprint
    assert sec_result.key_algorithm == pub_result.key_algorithm
    assert [u.uid for u in sec_result.user_ids] == [u.uid for u in pub_result.user_ids]

    # the output message schema itself has no field capable of carrying secret key material
    field_names = {f.name for f in sec_result.DESCRIPTOR.fields}
    assert not any("secret" in n and n != "is_secret" for n in field_names)


def test_extract_key_metadata_fingerprint_independent_oracle():
    """Cross-check the fingerprint against a from-scratch RFC 4880 SS12.2
    V4-fingerprint computation (SHA-1 over 0x99 || length || body), applied
    to the primary key packet's body bytes located by hand (new-format
    header: byte0=0xC6, 1-byte length since body<192) -- independent of
    pgpy's own PubKeyV4.fingerprint property that the node relies on."""
    ax = FakeContext()
    dearmored = dearmor(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert dearmored.ok is True
    data = bytes(dearmored.data)
    assert data[0] == 0xC6          # new-format header, tag 6 (PublicKey)
    body_len = data[1]              # 1-byte length form (body_len < 192)
    assert body_len < 192
    body = data[2:2 + body_len]

    oracle_fingerprint = v4_fingerprint_independent(body)

    result = extract_key_metadata(ax, PgpBlob(armored=load_fixture("pubkey.asc")))
    assert result.fingerprint == oracle_fingerprint


def test_extract_key_metadata_garbage_input_is_error():
    ax = FakeContext()
    result = extract_key_metadata(ax, PgpBlob(binary=b"garbage not a key"))
    assert result.ok is False
    assert result.error != ""


def test_extract_key_metadata_empty_input_is_error():
    ax = FakeContext()
    result = extract_key_metadata(ax, PgpBlob())
    assert result.ok is False
