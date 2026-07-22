from pgpy import PGPKey
from pgpy.errors import PGPError

from gen.messages_pb2 import PgpBlob, KeyMetadataResult, UserIdEntry, SubkeyEntry
from gen.axiom_context import AxiomContext
from nodes._common import (
    PgpParseError,
    enum_name,
    key_size_and_curve,
    primary_key_flags_names,
    resolve_blob,
    rfc3339,
    subkey_key_flags_names,
)


def _uid_entries(pgp_key):
    entries = []
    for uid in pgp_key.userids:
        try:
            revoked = any(
                enum_name(getattr(sig, "type", None)) == "CertRevocation"
                for sig in getattr(uid, "_signatures", [])
            )
        except Exception:
            revoked = False
        entries.append(UserIdEntry(
            uid=uid.userid or "",
            name=uid.name or "",
            comment=uid.comment or "",
            email=uid.email or "",
            primary=bool(uid.is_primary),
            revoked=revoked,
        ))
    return entries


def _subkey_entries(pgp_key):
    entries = []
    for key_id, sub in pgp_key.subkeys.items():
        size_bits, curve = key_size_and_curve(sub)
        expires_at = sub.expires_at
        try:
            revoked = bool(list(sub.revocation_signatures))
        except Exception:
            revoked = False
        try:
            binding_present = any(
                enum_name(getattr(sig, "type", None)) == "Subkey_Binding"
                for sig in sub.self_signatures
            )
        except Exception:
            binding_present = False
        entries.append(SubkeyEntry(
            fingerprint=str(sub.fingerprint),
            key_id=str(sub.fingerprint.keyid),
            key_algorithm=enum_name(sub.key_algorithm),
            key_size_bits=size_bits,
            curve=curve,
            created=rfc3339(sub.created),
            has_expiration=expires_at is not None,
            expires_at=rfc3339(expires_at),
            key_flags=subkey_key_flags_names(sub),
            revoked=revoked,
            binding_signature_present=binding_present,
        ))
    return entries


def extract_key_metadata(ax: AxiomContext, input: PgpBlob) -> KeyMetadataResult:
    """Parse an OpenPGP public or secret key (a lone key packet or a full
    Transferable Public/Secret Key with User IDs and subkeys) into structured
    public metadata -- primary key fingerprint, key ID, algorithm, size/curve,
    creation time, expiration, key flags, every User ID, and every subkey.
    is_secret reports whether the blob carries secret key packets, but NO
    secret key material is ever read or returned -- only public metadata,
    even for a secret key. Malformed input returns a structured error.
    """
    try:
        raw, _was_armored, _block_type = resolve_blob(input)
    except PgpParseError as e:
        return KeyMetadataResult(ok=False, error=str(e))

    try:
        key, _ = PGPKey.from_blob(raw)
    except (ValueError, PGPError) as e:
        return KeyMetadataResult(ok=False, error=f"failed to parse key: {e}")
    except (AttributeError, TypeError):
        # pgpy raises these (rather than its own ValueError/PGPError) when the
        # blob parses as *some* OpenPGP object but not a key -- e.g. a
        # detached signature or a bare message. Give a clean, specific
        # message instead of leaking the internal attribute-access error.
        return KeyMetadataResult(ok=False, error="input does not contain a parseable OpenPGP key packet")
    except Exception as e:
        return KeyMetadataResult(ok=False, error=f"failed to parse key: {e}")

    if not key.is_primary:
        return KeyMetadataResult(ok=False, error="input is a bare subkey packet, not a primary key -- ExtractKeyMetadata expects a primary key (a full Transferable Public/Secret Key, or its lone primary key packet)")

    size_bits, curve = key_size_and_curve(key)
    expires_at = key.expires_at
    key_flags = primary_key_flags_names(key)

    return KeyMetadataResult(
        ok=True,
        is_secret=not key.is_public,
        fingerprint=str(key.fingerprint),
        key_id=str(key.fingerprint.keyid),
        key_algorithm=enum_name(key.key_algorithm),
        key_size_bits=size_bits,
        curve=curve,
        created=rfc3339(key.created),
        has_expiration=expires_at is not None,
        expires_at=rfc3339(expires_at),
        key_flags=key_flags,
        user_ids=_uid_entries(key),
        subkeys=_subkey_entries(key),
    )
