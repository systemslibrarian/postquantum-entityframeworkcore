# Security Policy

PostQuantum.EntityFrameworkCore protects sensitive data. We take its correctness and its
threat model seriously, and we would rather hear about a problem from you than from an
incident report.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ Yes — current line, receives security fixes. |
| < 0.1   | ❌ No (no such releases). |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately via GitHub Security Advisories:
<https://github.com/systemslibrarian/postquantum-entityframeworkcore/security/advisories/new>

Or email **systemslibrarian@gmail.com** with the subject line
`SECURITY: PostQuantum.EntityFrameworkCore`.

Please include:

- A description of the issue and its impact.
- The affected version(s) and target framework(s).
- Reproduction steps or a proof of concept, if you have one.
- Any suggested remediation.

**What to expect**

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- Coordinated disclosure: we will agree a timeline with you, fix the issue, publish an
  advisory crediting you (unless you prefer to remain anonymous), and release a patched
  version.

## Scope

In scope:

- Cryptographic correctness of the envelope format and the AES-256-GCM and ML-KEM-768
  schemes (e.g. nonce handling, associated-data binding, key-id confusion, downgrade).
- Memory-handling of key material (zeroization, accidental exposure).
- Authentication-bypass, tampering-not-detected, or oracle-style information leaks.
- Supply-chain integrity of this repository's build and packaging.

Out of scope (by design — see [KNOWN-GAPS.md](KNOWN-GAPS.md) and the README threat model):

- Compromise of the host application process, its memory, or the key store it uses.
- Key custody, rotation scheduling, and auditing — these belong to your key-management
  layer (e.g. PostQuantum.KeyManagement / HSM / KMS).
- Information leaked by *unencrypted* columns, ciphertext length, or application logs.
- Querying/searchability limitations (these are intentional properties, not bugs).

## Cryptographic posture

- **Authenticated encryption only.** All data is encrypted with AES-256-GCM; the envelope
  header (version, scheme, key id) is bound in as associated data. There is no unauthenticated
  mode.
- **Standard, BCL-backed primitives.** `AesGcm`, `HKDF`, and `MLKem` come from the .NET base
  class library. We do not ship our own implementations of cryptographic primitives.
- **Post-quantum key wrapping.** The hybrid scheme wraps a per-value data key to ML-KEM-768
  (FIPS 203). The symmetric layer (AES-256) is itself a conservative post-quantum choice.
- **Fail closed.** On any authentication failure, malformed envelope, unknown scheme, or
  missing key, the library throws `PostQuantumCryptographicException` and never returns
  tampered or partial plaintext. Error messages are deliberately generic to avoid oracles.
- **Key hygiene.** Key material is copied into owned buffers and zeroized on `Dispose` via
  `CryptographicOperations.ZeroMemory`. Derived data keys are zeroized after each operation.

## Hardening recommendations for adopters

- Source keys from a managed key store (HSM/KMS/PostQuantum.KeyManagement), never from
  source control or configuration files.
- Rotate data-encryption keys on a schedule; the library keeps old values readable by key id.
- Keep decrypted values out of logs, traces, and caches.
- On platforms with ML-KEM support, prefer the `MLKem768Aes256Gcm` scheme for new data.

> To God be the glory — 1 Corinthians 10:31
