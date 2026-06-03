# Contributing

Thank you for considering a contribution. This is a security-sensitive library, so we hold a
high bar for changes — especially anything touching cryptography or the on-disk format.

## Ground rules

- **Be honest about limitations.** If a change has a caveat, document it (README,
  KNOWN-GAPS.md, or XML docs). We would rather ship an accurate, modest claim than an
  impressive, fragile one.
- **No new cryptographic primitives.** Use the .NET BCL (`AesGcm`, `HKDF`, `MLKem`, …). Do not
  hand-roll ciphers, KDFs, or random number generation.
- **Never break the envelope format silently.** The `PQE1` format and scheme ids are a
  compatibility contract. Format changes require a new version byte and round-trip tests for
  both old and new.
- **Fail closed.** Decryption paths must throw `PostQuantumCryptographicException` on any
  doubt and must not leak which check failed.

## Development

```bash
dotnet build -c Release
dotnet test  -c Release                  # net8.0, net9.0, net10.0
dotnet format --verify-no-changes        # style gate
dotnet run --project samples/ClinicRecords
```

The build treats warnings as errors and runs the .NET analyzers, including the crypto rules
(CA5350/CA5351). Public APIs require XML documentation.

## Tests

- Add tests for every behavior change. Crypto changes need: a round-trip test, a
  tamper/negative test, and (for format changes) an old-format decrypt test.
- Keep ML-KEM tests platform-aware: assert the round-trip where `IsSupported`, and the
  `PlatformNotSupportedException` path otherwise. Use the deterministic test KEM to cover the
  envelope logic everywhere.

## Reporting security issues

Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).

## Commit & PR

- Small, focused commits with clear messages.
- Update CHANGELOG.md under "Unreleased" for user-visible changes.
- By contributing you agree your work is licensed under the project's [MIT license](LICENSE).

> To God be the glory — 1 Corinthians 10:31
