# Claude Usage Uploader v2.0.7

The Drive upload folder is now controlled from the server. This is the last
release that will ever be needed to change where reports are written.

## Why

`DRIVE_FOLDER_ID` was a constant compiled into the binary. Relocating the report
folder therefore meant rebuilding and redistributing the executable to every
machine — including the dormant ones that never self-update, which have to be
visited in person. A one-line configuration change cost a full fleet rollout.

## What changed

- **`driveFolderId` now arrives on every trigger poll.** Agents adopt it within
  60 seconds. The folder is set from the dashboard (`setUploadDriveFolderId`),
  with no rebuild and no desk visits.
- **The compiled folder remains the fallback.** An empty server value means "use
  the built-in folder", which is the safe default and cannot break anything.
- **Malformed values are rejected, not applied.** The ID must look like a Drive
  ID before it reaches a Drive query; anything else is logged and ignored.
- **A folder the agent cannot write to degrades instead of failing.** On a
  `404`/`403` the agent logs CRITICAL, reverts to the compiled default, and
  retries there. A mistyped folder in the dashboard means "reports still arrive,
  in the old place" — never "the fleet silently stops reporting".
- **The active folder is persisted to `config.json`**, so a restart before the
  first poll still uses the last known-good value rather than snapping back.
- The service-loop startup line now records the folder in use, so
  `%TEMP%\claude-uploader.log` shows where a machine is actually writing.

## Rollout

Running agents self-update from the Gist within 24 hours. Dormant agents never
will and need `Repair-Claude-Uploader.cmd` run locally as administrator.

Pre-v2.0.7 agents simply ignore the new field and keep using their compiled
folder, so a mixed fleet is safe: nothing changes for them until they update.

## ⚠ The service account, not the script

Agents authenticate to Drive as the **service account** in
`service-account-key.json`. The dashboard's validation can only prove that the
*Apps Script owner* can see a folder — it says nothing about the service account.

Before pointing the fleet at a new folder, grant the service account **Editor**
on it. Otherwise every upload 404s and every agent silently falls back to the old
folder — which is the safe outcome, but not the one you intended.

## Also in this release

Carried forward from v2.0.6: redirects are re-POSTed so the request body survives
(the cause of months of `sig_mismatch`), non-JSON responses are treated as
failures rather than successes, and the webhook HMAC secret was rotated.
