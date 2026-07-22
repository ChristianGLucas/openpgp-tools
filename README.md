# openpgp-tools

An [Axiom](https://axiom.dev) node package for deterministic, offline structural parsing of
OpenPGP objects (RFC 4880 / RFC 9580) — public/secret keys, detached signatures, and messages.
Built for the Axiom marketplace.

Wraps [PGPy](https://github.com/SecurityInnovation/PGPy) (BSD-3-Clause). PGPy's full runtime
dependency tree — `cryptography` (Apache-2.0 OR BSD-3-Clause), `cffi` (MIT-0), `pyasn1`
(BSD-2-Clause), `pycparser` (BSD-3-Clause) — is permissively licensed with no copyleft.

## Scope

This package parses OpenPGP **structure and metadata only**. It never decrypts a message and
never signs or cryptographically verifies anything that requires secret key material. Parsing a
Transferable Secret Key extracts only its public-facing metadata (fingerprint, algorithm,
validity, User IDs, subkeys) — no secret scalar or MPI value is ever read or returned. The one
verification it performs (`ValidateStructure`'s self-signature check) is a pure public-key
structural check, exactly like checking a self-signed X.509 certificate's own signature — never a
trust decision.

Every node takes input as raw binary or ASCII-armored text (`PgpBlob`), bounded to 11 MiB
(comfortably under the platform's ~16 MiB deployed-invocation ingress limit once base64/JSON
framing overhead is accounted for), and returns a structured error rather than crashing on
malformed input.

## Nodes

- **ParsePackets** — walk any OpenPGP blob packet-by-packet: RFC packet tag, header format,
  declared length, and a brief type-specific detail string for each packet. Transparently descends
  into compressed-data packets.
- **ExtractKeyMetadata** — a public or secret key's fingerprint, key ID, algorithm, size/curve,
  validity, key flags, User IDs, and subkeys.
- **ParseSignaturePacket** — a standalone/detached signature or the leading signature in a larger
  blob: type, algorithms, validity, issuer, subpacket inventory.
- **Dearmor** — ASCII-armored text → raw binary, with CRC24 read-and-recomputed validation.
- **Enarmor** — raw binary → ASCII-armored text, CRC24 computed. Round-trips with Dearmor.
- **ValidateStructure** — structural well-formedness, object-kind classification, and (for keys)
  self-signature verification.
- **DescribeMessageStructure** — an encrypted/signed/compressed message's semantic envelope:
  recipients, integrity protection, compression, signature count, and (only when unencrypted) the
  literal-data envelope.

## License

MIT. See `LICENSE`.
