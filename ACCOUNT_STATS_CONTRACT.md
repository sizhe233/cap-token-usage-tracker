# Account usage statistics contract

## Scope

The CAP plugin records usage consumption by selected host credential. It does not fetch or persist provider quota balances. The Management Center may display live quota data separately through its existing provider quota adapters.

## Account identifier

The host UsageRecord supplies `AuthIndex`. CAP derives an opaque `account_ref` with a dedicated HMAC secret:

```text
account_ref = acct_ + lowercase-hex(HMAC-SHA256(account_tracking_secret, AuthIndex)[:16])
```

The raw AuthIndex, AuthID, filename, e-mail, account label, and provider credential JSON are never persisted or returned by the account-statistics endpoint.

`account_tracking_secret` is independent from `api_key_secret`. An empty value disables account-level attribution; usage records remain available in aggregate/provider/model views. A configured value must be at least 32 bytes. Rotating it starts a new account-identity generation; it must not reinterpret old references under the new secret.

## Ingestion

- Keep AuthIndex transient in `normalizedUsage` only until the account reference is derived.
- Derive the reference before the usage object is sent to persistence.
- Do not call host runtime-auth lookup for account attribution.
- If AuthIndex is missing or the account secret is disabled, attribute the record to no account rather than guessing from Source, e-mail, filename, AuthID, or API key.

## Persisted account dimensions

Each aggregate and request detail may contain only:

- `account_ref` (opaque, lowercase, fixed-format)
- provider/model/alias/source/executor/auth type/service tier/reasoning effort
- counters, timestamps, result and latency metadata already covered by the base contract

Account references are included only in the CPA Management-authenticated account-stats response. Normal resource responses are redacted and remove `account_ref`.

## Batch endpoint

The plugin exposes a Management API route:

```http
POST /v0/management/plugins/<id>/account-stats
Authorization: Bearer <CPA management key>
Content-Type: application/json
```

Request:

```json
{
  "auth_indexes": ["<transient AuthIndex>", "..."] ,
  "range": "24h"
}
```

The endpoint returns at most 100 requested account summaries per call. It accepts only the current authenticated Management request; no raw identity is echoed:

```json
{
  "schema_version": 1,
  "range": "24h",
  "generated_at": "...",
  "account_tracking_enabled": true,
  "account_refs": ["acct_<opaque-ref>", ""],
  "accounts": {
    "acct_<opaque-ref>": {
      "requests": 0,
      "failed_requests": 0,
      "input_tokens": 0,
      "output_tokens": 0,
      "reasoning_tokens": 0,
      "cache_read_tokens": 0,
      "cache_creation_tokens": 0,
      "total_tokens": 0,
      "estimated_cost_usd": 0,
      "last_used": "..."
    }
  }
}
```

`account_refs` preserves the exact request order, including empty entries for missing indexes. `accounts` contains only matching opaque references.

## Quota separation

The account summary is historical consumption, not remaining quota. Remaining credits, reset instants, rate limits, and provider plan state are read-only live values from existing Management Center quota adapters. They must not be inferred from token counters or silently persisted as if authoritative.
