#!/usr/bin/env bash
#
# Generates a CycloneDX Software Bill of Materials (SBOM) for the library project.
#
# The SBOM lists every NuGet dependency (direct and transitive) with versions, so adopters
# and auditors can review the exact supply chain of a build. Output is written to sbom/ as
# JSON and is intentionally git-ignored — regenerate it per release/commit rather than
# committing a stale artifact.
#
# Usage:  ./scripts/generate-sbom.sh
# Requires: .NET SDK and network access on first run (to restore the CycloneDX tool).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROJECT="src/PostQuantum.EntityFrameworkCore/PostQuantum.EntityFrameworkCore.csproj"
OUT_DIR="sbom"

echo "Restoring local tools (CycloneDX)…"
dotnet tool restore

mkdir -p "$OUT_DIR"

echo "Generating CycloneDX SBOM for $PROJECT…"
dotnet dotnet-CycloneDX "$PROJECT" \
    --output "$OUT_DIR" \
    --output-format json \
    --filename sbom.cdx.json

echo "SBOM written to $OUT_DIR/sbom.cdx.json"
