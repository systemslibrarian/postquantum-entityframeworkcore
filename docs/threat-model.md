# Threat model

This document expands on the summary in the [README](../README.md#threat-model). Read it
before relying on the library for anything that matters.

## Assets

- **Sensitive column values** — PII, PHI, financial data, secrets/tokens stored in encrypted
  columns.
- **Key material** — the data-encryption keys (DEKs) and, for the hybrid scheme, the ML-KEM
  key-encapsulation keys (KEKs).

## Adversaries we defend against

| Adversary | Capability | Outcome with this library |
| --- | --- | --- |
| **Database thief** | Obtains a copy of the database file, a backup, or a storage snapshot. | Sees only authenticated ciphertext. Cannot read protected values without the keys. |
| **Tamperer** | Can modify bytes in the database (e.g. compromised storage, MITM on replication). | Any modification to ciphertext, nonce, tag, scheme byte, or key id fails the GCM tag; decryption throws and never returns altered plaintext. |
| **Downgrader** | Tries to force a value to be read under a weaker scheme. | The scheme id is authenticated as associated data; tampering with it breaks authentication. |
| **Harvester ("harvest now, decrypt later")** | Records ciphertext today to decrypt with a future quantum computer. | With the `MLKem768Aes256Gcm` scheme, the key-wrapping layer is ML-KEM-768; captured data is not unlocked by quantum attacks on the asymmetric layer. AES-256 keeps ~128-bit strength against Grover. |

## Adversaries we do NOT defend against

| Adversary | Why it's out of scope |
| --- | --- |
| **Compromised application process** | If an attacker runs code in your process or reads its memory, they can obtain the live keys and plaintext. Defend with OS/process hardening, least privilege, and a key store that limits exposure. |
| **Compromised key store** | If the HSM/KMS/key-management layer is breached, encryption cannot help. Key custody is that layer's responsibility. |
| **Plaintext sprawl** | Logs, traces, caches, search indexes, debuggers, and crash dumps may capture decrypted values. Keep secrets out of these paths. |
| **Side channels / length & timing** | Ciphertext length reveals plaintext length (± fixed overhead). The library uses constant-comparison primitives from the BCL but does not defend against all microarchitectural side channels. |
| **Correlation via other columns** | Unencrypted columns (timestamps, foreign keys, status) can still be used to link or infer. Encrypt or generalize them if that matters. |

## Cryptographic design decisions

- **AEAD everywhere.** AES-256-GCM provides confidentiality *and* integrity. There is no
  unauthenticated mode to misuse.
- **Associated-data binding.** The envelope header is the GCM associated data, so metadata
  (version/scheme/key id) is integrity-protected even though it is stored in the clear.
- **Per-value randomness.** A fresh 96-bit nonce per value (and a fresh KEM encapsulation per
  value in the hybrid scheme) prevents equality correlation and nonce reuse within a key.
- **HKDF domain separation.** The hybrid scheme derives the data key with HKDF-SHA256 using
  the key id as salt and a fixed context string as info, separating keys across ids and
  schemes.
- **Fail closed, quiet errors.** All failures raise a single generic
  `PostQuantumCryptographicException` so error text cannot act as a decryption oracle.
- **Key zeroization.** DEKs, KEK private material, and derived data keys are zeroized after
  use / on dispose via `CryptographicOperations.ZeroMemory`. (Note: managed memory and
  swapping limit what zeroization can guarantee; it is best-effort defense in depth.)

## Operational guidance

- Keep keys in a managed store; rotate DEKs on a schedule.
- Prefer the ML-KEM hybrid scheme for new data on supported platforms.
- Treat decrypted values as toxic: minimize where they live and how long.
- Pad values whose *length* is sensitive before storing them.

> To God be the glory — 1 Corinthians 10:31
