# Vici Inbox staging setup

This repository is the isolated proving ground for Vici Inbox. It must never
contain production customer data, message history, recordings, device tokens,
or credentials. The production app is unchanged until a reviewed staging
commit is deliberately promoted.

## What is separate

- GitHub repository and `agent/*` review branches
- Railway service, domain, environment variables, and deployment history
- Supabase project and all application data
- iOS bundle ID: `com.vicipeptides.inbox.staging`
- iOS display name, Keychain namespace, APNs registration, and TestFlight app
- login password, session secret, GHL bridge secret, and Apple push setup

The existing Telnyx phone number and its approved 10DLC campaign can be reused.
Do not move the number to another campaign. Staging outbound messages set their
own delivery callback URL and can only target `STAGING_ALLOWED_RECIPIENTS`.

## Safe setup order

1. Rotate the GitHub token and Supabase service-role key that were shared in
   chat. Put replacement values only in GitHub/Railway secret stores.
2. In the new Supabase project's SQL Editor, run
   `scripts/staging-bootstrap.sql`. This creates empty structure only; it does
   not copy production data.
3. Create a new Railway service from this repository. Do not connect the
   production service or production database.
4. Add the variables below in Railway. Start with
   `ENABLED_INTEGRATIONS=telnyx`; leave automations, WooCommerce, ShipStation,
   GHL, voice, and AI disabled until their staging-specific checks pass.
5. Generate the Railway HTTPS domain. Set the same URL in `APP_URL` and in the
   GitHub repository variable `VICI_STAGING_SERVER_URL`.
6. Confirm `/health` reports `environment: staging`, then run the read-only UI
   checks before sending anything.
7. Add only the owner's E.164 test number to `STAGING_ALLOWED_RECIPIENTS` and
   perform one outbound SMS. A different recipient must be rejected locally.
8. Create the separate Apple App ID/App Store Connect record, APNs setup, and
   TestFlight internal group for the staging bundle before running the iOS
   upload workflow.

## Railway variables

Use `.env.example` as the canonical list. At minimum:

```text
NODE_ENV=production
APP_ENVIRONMENT=staging
APP_URL=https://<staging-service>.up.railway.app
ENABLED_INTEGRATIONS=telnyx
CORS_ALLOWED_ORIGINS=https://<staging-service>.up.railway.app
STAGING_ALLOWED_RECIPIENTS=+<owner-test-number>
SUPABASE_URL=<new-staging-project-url>
SUPABASE_SERVICE_KEY=<rotated-staging-service-role-key>
SESSION_SECRET=<new-random-value-at-least-32-characters>
INBOX_PASSWORD=<new-staging-only-password-at-least-12-characters>
TELNYX_API_KEY=<secret>
TELNYX_PUBLIC_KEY=<Mission-Control-public-key>
TELNYX_MESSAGING_PROFILE_ID=<existing-approved-profile-id>
TELNYX_PHONE_NUMBER=<existing-business-number>
```

Never put the service-role key, API keys, passwords, SIP credentials, APNs key,
or personal test number in Git. The Supabase publishable/anon key is not needed
by this architecture because clients talk to Railway, not Supabase directly.

## Same Telnyx number: important routing limit

One approved number is enough for outbound staging SMS; the code supplies a
per-message staging delivery webhook. Incoming SMS and calls are different:
their default destination remains the single webhook configured on the Telnyx
Messaging Profile or Voice API Application.

Therefore, do **not** replace the production inbound webhook with the staging
URL. Before testing inbound staging traffic on the shared number, deploy and
validate a signed routing gateway that sends only the allowlisted owner's
traffic to staging and sends everything else to production. It must preserve
the exact request body and Telnyx signature headers. Until that gateway exists,
inbound replies and calls continue to production by design.

## Phase-two security acceptance checks

- Unsigned, stale, tampered, replayed, wrong-profile, wrong-number, and
  wrong-connection Telnyx requests are rejected.
- WooCommerce HMAC and current GHL Ed25519 signatures are required when those
  integrations are enabled.
- The custom GHL send bridge requires an Authorization bearer secret and an
  idempotency key; secrets in URLs or request bodies are rejected.
- CORS uses exact origins and state-changing browser requests reject untrusted
  origins.
- Startup fails when a required safety value is absent or weak.
- Disabled integrations return `503` at their public/API boundary; possessing a
  stale credential alone cannot silently turn an integration back on.
- Shared-login sessions expire after seven days instead of thirty; individual
  revocable accounts and MFA belong to the later identity phase.
- Logs mask phone numbers and Swift release logs treat values as private.
- RLS blocks publishable/anonymous access to staging application tables.
- No production rows, credentials, or push tokens exist in staging.

## Promotion rule

Promote reviewed commits, never databases or environment files. After tests
pass in staging, cherry-pick or merge the approved code changes into the
production repository and repeat production validation. Never replace the
production database with staging or copy staging secrets into production.
