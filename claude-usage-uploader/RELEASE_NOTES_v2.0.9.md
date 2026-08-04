# Claude Usage Uploader v2.0.9

Two changes, and the second one is a change of server.

## 1. The replay queue could no longer recover from an outage

The agent keeps a queue of pings it failed to deliver and retries them on a timer. That
queue was **unbounded**, and every cycle replayed **all** of it - one HTTP request per
entry - re-queueing anything that failed again.

That turns a brief server hiccup into a permanent outage:

```
server busy -> pings fail -> queue grows -> next cycle sends MORE requests
            -> server busier -> queue grows faster -> nothing ever drains
```

Fleet request rate was `agents x queueLength / 300s`. Measured with 22 machines:

| Queue length | Old rate | New rate |
|---|---|---|
| 10 | 0.7/s | 0.7/s |
| 50 | 3.7/s | 1.5/s |
| 100 | 7.3/s | 1.5/s |
| **500** | **36.7/s** | **1.5/s** |

Healthy baseline is 0.44/s. At a 500-entry backlog the fleet alone offered 36.7 requests
a second - and because a refused request never drains from the queue, the outage sustained
itself indefinitely. It did not recover on its own; it had to be broken manually.

Three independent bounds now apply, because any one alone is insufficient:

- **Hard cap of 200 entries**, oldest dropped, enforced at write time so the file cannot
  grow even if replay never runs
- **24-hour expiry** - a machine offline for a week no longer wakes up and replays a week
  of dead heartbeats
- **20 per cycle** - the important one: request rate is now *constant* regardless of
  backlog. A backlog drains more slowly instead of hitting the server harder

Plus immediate backoff when the server returns an HTML error page, and per-process jitter
so machines that rebooted together stop converging on the same 5-minute boundary.

## 2. Reporting moved off Google Apps Script

Apps Script enforces a hard ceiling of **~30 simultaneous executions per Google account**.
It cannot be raised and there is no paid tier. With 22 machines reporting continuously (77
registered) that ceiling was reached repeatedly, the admin dashboard became unusable, and
Apps Script offers no metrics to diagnose it with.

Reporting now goes to a .NET service:

```
https://claudeusage.sigmasolve.com/exec
```

**The wire protocol is unchanged.** Same HMAC-SHA256 signing over `ts + "." + body`, same
`?_ts=&_sig=` parameters, same payload, same `checkTrigger` response shape. This is only a
change of host - verified by a 29-assertion suite that signs requests exactly as this agent
does and checks every field the agent reads back.

**Report files still upload straight to Google Drive** via the service account. That path
never involved Apps Script and is untouched.

### Rollback is a config edit, not a release

The endpoint is overridable per machine. In
`%APPDATA%\ClaudeUsageUploader\config.json`:

```json
{ "name": "Firstname_Lastname", "webhookUrl": "https://script.google.com/macros/s/AKfy.../exec" }
```

Only `https://` values are accepted - the agent uses the https module exclusively, so an
`http://` value would fail every request in a way that looks like the server being down.

Without this, rolling back one machine would mean building and shipping a whole new
release. This way it is one line of JSON on that machine.

### The endpoint is now logged

`%TEMP%\claude-uploader.log` records which server the agent reports to at startup:

```
Reporting to https://claudeusage.sigmasolve.com/exec (compiled default)
```

Which server a machine talks to is the most useful fact when diagnosing "why is this
machine missing from the dashboard", and it used to be invisible.

## Rollout

**Pilot on ONE machine first.** This release combines a bug fix with a change of server,
which is more than one variable. Verify on a single machine that it appears on the new
dashboard with version 2.0.9 and that a report still lands in Drive, before letting the
rest auto-update.

Running agents self-update from the Gist within the hour. Dormant machines need
`Repair-Claude-Uploader.cmd` run locally as administrator.

Mixed fleets are safe: pre-2.0.9 agents keep reporting to Apps Script, 2.0.9 agents report
to the new service. Both are recorded, just in different places - so keep the Apps Script
dashboard available until the whole fleet has moved.

## Also in this release

Carried forward from v2.0.8: `ccusage claude daily` is used explicitly (the bare form no
longer reliably finds Claude Code data), and on-demand backdated reports via `DATED_RUN`.
