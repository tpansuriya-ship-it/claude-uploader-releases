# Claude Usage Uploader v2.0.6

Critical reporting fix. Every agent up to and including v2.0.5 silently lost its
status pings; this release restores them.

## The bug

Apps Script answers a POST to `/exec` with a `302` to `script.googleusercontent.com`.
Up to v2.0.5 the client followed that redirect with `https.get()` — a **GET with no
body**. The `_ts` / `_sig` query parameters survived the hop, but the JSON payload did
not, so the server hashed `ts + '.' + ''` while the client had signed
`ts + '.' + <payload>`. Every redirected ping was therefore rejected as
`sig_mismatch`.

The signature was never wrong. The request body was being discarded in transit, and
the error message pointed at the wrong cause — the secret — for weeks.

A second defect hid the first: a non-JSON response was treated as **success**. When a
restricted deployment returned an HTML sign-in page, the agent recorded the ping as
delivered, so the retry queue never engaged and nothing appeared in any log. The
dashboard showed the entire fleet as Offline while uploads to Drive continued
normally, because Drive uploads use the service account and never touch the webhook.

## What changed

- **Redirects are re-POSTed** with the original body and headers, so the signature
  stays valid across the hop.
- **A non-JSON response is now a failure**, not a success. The retry queue engages and
  the local log names the cause — including explicitly detecting a Google sign-in page
  and telling you to set the deployment's access to `Anyone`.
- **A failed redirect hop is a failed ping.** v2.0.5 reported `ok: true` on redirect
  error and timeout, which is what made delivery failures invisible.
- **The webhook HMAC secret is rotated.** The previous value shipped in a public
  repository across several releases and could be used to forge pings for any
  developer. The server accepts both values during rollout.
- **The repair script no longer aborts when the scheduled task is absent.**
  `schtasks` writes to stderr in that case, and under `$ErrorActionPreference = 'Stop'`
  a redirected native stderr becomes a terminating error — so the repair failed at its
  first step on precisely the machines it exists to fix.
- **The release pipeline is parameterised.** The version lived in ten hardcoded places
  across `build.yml` and `package.json`; it now derives from `RELEASE_VERSION`.

## Rollout

Running agents self-update from the Gist within 24 hours of it being published — no
desk visits. Agents that are not running will never self-update and need
`Repair-Claude-Uploader.cmd` run locally as administrator.

After publishing:

1. Update the Gist manifest to `2.0.6` with this release's checksums from
   `SHA256SUMS.txt`.
2. Re-run `setupUtilityDistribution` in Apps Script so the dashboard's drift detection
   and reminder emails agree with the Gist.
3. Once the Version Matrix shows nobody below v2.0.6, empty
   `WEBHOOK_HMAC_SECRET_RETIRED` in `Code.gs`. Until then the old, publicly known
   secret is still accepted and pings remain forgeable.

## Known limitation

The rotated secret is still committed to source, so it is only as private as the
repository. Injecting it at build time from a CI secret is the durable fix.
