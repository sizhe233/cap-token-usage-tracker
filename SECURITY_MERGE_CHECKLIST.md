# Security invariants for upstream merges

This fork is pinned to the audited upstream baseline `v2.0.3` (`4bcf440844bbfef4bb29f120f1c6c57ac761a07e`). Do not merge upstream changes blindly. Review each upstream commit and preserve every invariant below.

## Authentication boundary

- `/v0/resource/plugins/<id>/dashboard` and `/full-dashboard` may return static HTML shells only.
- Every resource route that returns or mutates runtime data must require a valid `X-Full-Mode-Session` token:
  - `/stats`, `/stats/initial`, `/stats/trends`, `/stats/groups`
  - `/requests`, `/costs`, `/exchange-rate`, `/prices`, `/preferences`
  - every `/full-mode/*` route except the static `/full-dashboard` shell
- Session issuance must remain under authenticated CPA Management API:
  `POST /v0/management/plugins/<id>/full-mode/session`.
- The dashboard must not fetch statistics before Management authentication succeeds.
- The CPA management key must never be stored in browser storage or plugin storage.
- Full-mode sessions remain random, in-memory, revocable, and no longer than five minutes.

## Data minimization

- API-key tracking remains disabled by default (`api_key_secret: ""`).
- Explicit API-key tracking secrets must be at least 32 bytes. The legacy public secret `123456` must remain rejected.
- Do not persist prompts, request bodies, response bodies, failure bodies, response headers, raw Auth IDs, raw Auth Indexes, account e-mails, account labels, or OAuth account identifiers.
- Do not call `host.auth.get_runtime` or any credential save/import API.
- `Source` remains allowlisted. Unknown values, account-like strings, and token-like strings collapse to a canonical provider address or provider name.

## Network and filesystem

- No outbound request occurs during plugin registration, reconfiguration, or normal usage ingestion.
- Any retained outbound endpoint must be a compile-time HTTPS constant with same-host redirect enforcement, response-size limits, and explicit user action.
- Database and handover files remain mode `0600`; parent directories remain mode `0700`.
- Restore remains size-limited, schema-validated, session/Management-authenticated, and atomic with rollback.

## Supply chain and release

- No compiled binaries are tracked in Git. CI rejects `.exe`, `.dll`, `.so`, `.dylib`, and generated `.h` files.
- GitHub Actions stay pinned to full commit SHAs.
- Default workflow permissions stay `contents: read`; only the gated release job gets `contents: write`.
- Ordinary branch pushes must never publish releases or prereleases.
- Fixed releases use the distinct plugin ID `cap-token-usage-tracker-sizhe233`.
- The plugin registry remains schema v2 direct-install with immutable release URLs, exact file sizes, and SHA-256 digests.

## Required merge procedure

1. Fetch the intended upstream tag or commit; record its full SHA.
2. Review the upstream diff against the last audited baseline, especially capabilities, routes, persistence schema, browser code, C bridge, dependencies, and workflows.
3. Re-apply or adapt all invariants above before merging.
4. Run `go test -count=1 ./...`, `go vet ./...`, the tracked-binary gate, and target-platform `c-shared` builds.
5. Review every generated release asset and checksum. Never reuse an upstream asset.
6. Publish a new audit-suffixed tag from this fork.
7. Update `registry.json` only after publication; pin exact URLs, sizes, and SHA-256 values.
8. Deploy only after verifying the downloaded archive and extracted library against the registry.
