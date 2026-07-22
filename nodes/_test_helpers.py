"""Shared test fixtures and independent-oracle helpers.

Fixtures under nodes/fixtures/ were generated ONCE via PGPy itself and
committed, so every test run is deterministic (no key generation at test
time). The KEY packets (primary + subkey, in pubkey.asc/seckey.asc) were
created with a fixed, pinned timestamp (2024-01-15T12:00:00Z) -- tests assert
against it directly. The SIGNATURE packets (the self-certification and
subkey-binding signatures embedded in those same fixtures, plus
detached_signature.asc / signed_message.asc) were made with PGPy's default
`.sign()`, which stamps the real wall-clock time the fixtures were generated
-- no test asserts an exact value for a signature's `created` field, only its
presence/format, so this does not affect determinism of what's actually
checked.

The oracle functions below (`crc24_independent`, `v4_fingerprint_independent`)
are hand-implemented directly from the RFC 4880 spec text, independent of
PGPy's own `Armorable.crc24` / `PubKeyV4.fingerprint` implementations that the
package under test relies on -- they exist so tests can prove correctness
against a second, from-scratch computation rather than merely checking
self-consistency with the library being wrapped.
"""
import os

_FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str) -> str:
    with open(os.path.join(_FIXTURES_DIR, name), "r") as f:
        return f.read()


def crc24_independent(data: bytes) -> int:
    """RFC 4880 SS6.1 CRC24, hand-implemented from the spec (generator
    0x1864CFB, init 0xB704CE) -- independent of pgpy.types.Armorable.crc24."""
    crc = 0x0B704CE
    for b in data:
        crc ^= (b << 16)
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def v4_fingerprint_independent(pubkey_packet_body: bytes) -> str:
    """RFC 4880 SS12.2 V4 fingerprint: SHA-1 over 0x99 || 2-byte body length ||
    body (version || creation-time || algorithm || key material), hand-
    implemented from the spec -- independent of pgpy's PubKeyV4.fingerprint."""
    import hashlib
    import struct
    return hashlib.sha1(b"\x99" + struct.pack(">H", len(pubkey_packet_body)) + pubkey_packet_body).hexdigest().upper()


class FakeContext:
    """Minimal AxiomContext implementation for unit tests."""

    class _Logger:
        def debug(self, msg: str, **attrs) -> None: pass
        def info(self, msg: str, **attrs) -> None: pass
        def warn(self, msg: str, **attrs) -> None: pass
        def error(self, msg: str, **attrs) -> None: pass

    class _Secrets:
        def get(self, name: str):
            return ("", False)

        def status(self, name: str):
            from gen.axiom_context import SecretStatus
            return SecretStatus.UNSET

    def __init__(self) -> None:
        self.log = self._Logger()
        self.secrets = self._Secrets()
        self.execution_id = "test-execution-id"
        self.flow_id = "test-flow-id"
        self.tenant_id = "test-tenant-id"
