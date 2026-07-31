# Claude Usage Uploader v2.0.8

Two changes: on-demand backdated reports, and a fix for a bug that was silently
emptying reports on newer installs.

## Reports were at risk of becoming silently empty

`ccusage` now covers many agent CLIs (Codex, Copilot, Gemini and others), and its
bare `daily` / `session` commands no longer reliably surface Claude Code data.
Measured on a machine holding four months of local Claude Code logs:

```
ccusage daily --json         ->  {"daily":[]}       (empty)
ccusage claude daily --json  ->  full 4-month history
```

Any machine that ended up with such a build would have produced a valid,
well-formed, **empty** report — no error, no failed upload, nothing to alert on.
It would simply have looked like that person had stopped using Claude.

Report generation now asks for the explicit `claude` subcommand and keeps the
bare form as a fallback, so older `ccusage` installs that predate subcommands
still work. The fallback fires only on a non-zero exit, never on a legitimately
empty result — a genuine "no usage this period" is still reported as such.

## On-demand backdated reports

A new `DATED_RUN` trigger asks a specific machine for a specific past period:

```
ccusage claude daily   --json --since <date> --until <date>
ccusage claude session --json --since <date> --until <date>
```

The agent uploads the result under a deliberately different filename:

```
Firstname_Lastname_claude_daily_ondemand_<since>_to_<until>.json
```

That naming matters. The weekly archive and the hourly mirror both match on the
exact `_claude_daily.json` / `_claude_session.json` suffix, so reusing it would
have swept a one-off ad-hoc pull into the Mon–Sun weekly folders and corrupted
the compliance record. The `_ondemand_` infix keeps the two streams separate, and
lets the dashboard parse the covered period back out of the filename.

Requests are made from the dashboard (Report Search page) and results are
downloadable there. A period with no activity is reported explicitly as
"no usage in this period" rather than as a failure or a silent success.

**Requires the machine to be online.** The request waits in the queue until that
agent next polls; a paused or removed agent ignores triggers entirely, and the
dashboard refuses those up front rather than queueing a request that can never
run.

## Rollout

Running agents self-update from the Gist within the hour. Dormant machines need
`Repair-Claude-Uploader.cmd` run locally as administrator.

Pre-v2.0.8 agents ignore `DATED_RUN` — a mixed fleet is safe, those machines just
cannot service an on-demand request until they update.

## Also in this release

Carried forward from v2.0.7: the Drive upload folder remains server-controlled,
with a fallback to the compiled folder if the configured one is unwritable.
