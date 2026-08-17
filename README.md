# Vici Inbox Staging

An isolated copy of Vici Inbox for security remediation and upgrade testing.
It has its own Railway service, Supabase project, native bundle identifier, and
TestFlight app. It may reuse the existing registered Telnyx business number,
but the backend refuses every outbound recipient not listed in
`STAGING_ALLOWED_RECIPIENTS`.

Start with [STAGING-SETUP.md](STAGING-SETUP.md). Create the empty database with
`scripts/staging-bootstrap.sql`; do not copy production customer data. Phase 2
rejects unsigned, stale, mismatched, or replayed provider events; restricts
CORS/CSRF; removes fallback secrets; rate-limits login; and keeps iOS logs
private. OpenRouter and recording privacy controls from Phase 1 are included.

Production is not connected to this repository and must never use its staging
database or staging iOS credentials.
