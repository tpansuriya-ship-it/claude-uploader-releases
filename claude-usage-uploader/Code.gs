// ================================================================
// Claude Usage Uploader — Compliance Dashboard (Google Apps Script)
// Code.gs (Server-side logic)
// ================================================================

// -------------------- WEBHOOK AUTH (v2) --------------------
// Default secret. v2: also reads `hmac_secret` from ScriptProperties when set,
// so the secret can be rotated without a code redeploy. Currently-deployed
// uploader binaries still sign with the constant — keeping it allows a
// rolling migration once binaries are redeployed.
// v2.0.6 fleet secret. Must match WEBHOOK_HMAC_SECRET in claude-usage-uploader.js.
var WEBHOOK_HMAC_SECRET_DEFAULT = 'ss-uploader-hmac-2026b-cab69d71b7b5cc93fe49e24818bc8cc2';

// Secrets from earlier releases, still accepted so agents that have not yet
// self-updated keep reporting. Each entry is a forgeable value — the whole point
// of rotating — so empty this array as soon as the Version Matrix shows nobody
// left below v2.0.6. Leaving it populated indefinitely makes the rotation moot.
var WEBHOOK_HMAC_SECRET_RETIRED = [
  'ss-uploader-hmac-2026-b7f3a9c1d4e2'  // <= v2.0.5. Published in a public repo.
];

var HMAC_STALE_SECS = 300;   // v2: tightened from 7200s (was a 2h replay window)
var HMAC_FUTURE_TOL = 300;   // Allow up to 5 minutes clock skew tolerance for drifted client machines

// Accept the Script Properties override, the compiled fleet secret, and any
// retired secrets during rolling upgrades. Previously, setting hmac_secret
// immediately invalidated every already-installed client and produced fleet-wide
// stalls.
function getWebhookSecrets_() {
  var secrets = [];
  try {
    var override = PropertiesService.getScriptProperties().getProperty('hmac_secret');
    if (override && override.length > 8) secrets.push(override);
  } catch (e) {}
  if (secrets.indexOf(WEBHOOK_HMAC_SECRET_DEFAULT) === -1) secrets.push(WEBHOOK_HMAC_SECRET_DEFAULT);
  for (var i = 0; i < WEBHOOK_HMAC_SECRET_RETIRED.length; i++) {
    if (secrets.indexOf(WEBHOOK_HMAC_SECRET_RETIRED[i]) === -1) {
      secrets.push(WEBHOOK_HMAC_SECRET_RETIRED[i]);
    }
  }
  return secrets;
}

// Surfaced by diagnoseWebhookAuth so you can tell at a glance whether the
// rotation is still carrying a forgeable legacy secret.
function getRetiredSecretCount_() {
  return WEBHOOK_HMAC_SECRET_RETIRED.length;
}

function computeHmac256_(secret, message) {
  var raw = Utilities.computeHmacSha256Signature(message, secret);
  return raw.map(function(b) { return ('0' + (b < 0 ? b + 256 : b).toString(16)).slice(-2); }).join('');
}

// v2: Constant-time string equality — avoids early-exit timing leaks even though
// the GAS sandbox makes this largely cosmetic; it's still good hygiene.
function safeEqual_(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// v2: Anti-replay nonce cache — signatures used within the staleness window
// are remembered for the full window length and can't be replayed.
function nonceSeen_(sig) {
  try {
    var cache = CacheService.getScriptCache();
    var key = 'nsig_' + sig.substring(0, 32);
    if (cache.get(key)) return true;
    cache.put(key, '1', HMAC_STALE_SECS + 30);
    return false;
  } catch (e) {
    return false; // fail-open on cache errors; tighter than crashing
  }
}

// Returns '' on success, or a short reason string on failure.
// v2: rejects future-dated timestamps, enforces a tight 5-min staleness
// window, and caches signatures to block replay within that window.
function verifyWebhookSignature_(e) {
  var ts  = (e.parameter && e.parameter._ts)  ? e.parameter._ts  : '';
  var sig = (e.parameter && e.parameter._sig) ? e.parameter._sig : '';
  if (!ts || !sig) return 'missing_params';
  var tsInt = parseInt(ts, 10);
  if (!isFinite(tsInt) || tsInt <= 0) return 'bad_ts';
  var now = Math.floor(Date.now() / 1000);
  var skew = now - tsInt; // positive = past, negative = future
  if (skew > HMAC_STALE_SECS) return 'stale_ts (' + skew + 's, limit ' + HMAC_STALE_SECS + 's)';
  if (skew < -HMAC_FUTURE_TOL) return 'future_ts (' + (-skew) + 's ahead of server)';
  var body = (e.postData && e.postData.contents) ? e.postData.contents : '';

  // v5.1: distinguish "body was lost in transit" from "signature is genuinely
  // wrong". Apps Script 302-redirects POSTs to script.googleusercontent.com, and
  // the ≤v2.0.5 client follows that redirect with https.get() — a bodyless GET.
  // The signature (a query param) survives; the payload does not. The server then
  // hashes ts+'.'+'' and can never match, which for months read as 'sig_mismatch'
  // and sent everyone hunting for a wrong secret. Name it accurately instead.
  if (!body) {
    return 'body_lost_in_transit (signature present but request carried no payload — ' +
           'the client followed a 302 with a bodyless GET, or the deployment is ' +
           'redirecting anonymous POSTs to a login page. Set the deployment access ' +
           'to "Anyone" and rebuild the client so redirects re-POST.)';
  }

  var secrets = getWebhookSecrets_();
  var matched = false;
  for (var i = 0; i < secrets.length; i++) {
    var expected = computeHmac256_(secrets[i], ts + '.' + body);
    if (safeEqual_(sig, expected)) matched = true;
  }
  if (!matched) return 'sig_mismatch';
  if (nonceSeen_(sig)) return 'replay_blocked';
  return '';
}

// -------------------- STATUS CONSTANTS --------------------
var STATUS = {
  REGISTERED:     'REGISTERED',
  HEARTBEAT:      'HEARTBEAT',
  WAITING:        'WAITING',
  PAUSED:         'PAUSED',
  WAITING_PAUSED: 'WAITING_PAUSED',
  PONG:           'PONG',
  POLLING_ACK:    'POLLING_ACK',
  GENERATE_START: 'GENERATE_START',
  GENERATE_DONE:  'GENERATE_DONE',
  UPLOAD_START:   'UPLOAD_START',
  UPLOAD_DONE:    'UPLOAD_DONE',
  SUCCESS:        'SUCCESS',
  FAILURE:        'FAILURE',
  UPDATED:        'UPDATED'
};

// Status types considered "noise" — v3: these update the developer's
// RegisteredDevelopers row in-place instead of appending log rows.
var NOISE_STATUSES = [STATUS.HEARTBEAT, STATUS.WAITING, STATUS.PONG, STATUS.PAUSED, STATUS.WAITING_PAUSED];

// -------------------- ADMIN ACCESS CONTROL (v2) --------------------
// v2: Admin allowlist is now backed by Script Properties (`admin_emails`,
// comma-separated). When the property is empty/unset, behaviour falls back to
// "no allowlist" (current pilot mode) so existing deployments keep working.
// Once the property is set, the gate is enforced strictly. Admins can edit
// the list from the Health page without redeploying.
var ADMIN_EMAILS = []; // legacy in-source fallback (still honoured if non-empty)

function getAdminAllowlist_() {
  var list = ADMIN_EMAILS.slice();
  try {
    var raw = PropertiesService.getScriptProperties().getProperty('admin_emails') || '';
    raw.split(/[,\s;]+/).forEach(function(em) {
      em = em.trim().toLowerCase();
      if (em && list.indexOf(em) === -1) list.push(em);
    });
  } catch (e) {}
  return list;
}

function isAdmin_(email) {
  if (!email) return false;
  var list = getAdminAllowlist_();
  if (list.length === 0) return true; // pilot mode — anyone authenticated
  return list.indexOf(String(email).toLowerCase()) !== -1;
}

function requireAdmin_() {
  var list = getAdminAllowlist_();
  if (list.length === 0) return; // pilot mode (no allowlist configured)
  var email;
  try { email = Session.getActiveUser().getEmail(); } catch (e) { email = ''; }
  if (!email || list.indexOf(email.toLowerCase()) === -1) {
    throw new Error('Unauthorized: ' + (email || 'anonymous') + '. Configure admin_emails in Script Properties.');
  }
}

// v2: surface allowlist state to the client (for the Health page editor)
function getAdminAllowlistInfo() {
  var email;
  try { email = Session.getActiveUser().getEmail(); } catch (e) { email = ''; }
  var list = getAdminAllowlist_();
  return {
    currentUserEmail: email,
    allowlist: list,
    pilotMode: list.length === 0,
    isAdminCurrentUser: isAdmin_(email)
  };
}

function setAdminAllowlist(emailsCsv) {
  // First admin to set the list also becomes one of its members (bootstrap).
  var existing = getAdminAllowlist_();
  if (existing.length > 0) requireAdmin_();
  var clean = String(emailsCsv || '').split(/[,\s;]+/).map(function(e) { return e.trim().toLowerCase(); }).filter(Boolean);
  PropertiesService.getScriptProperties().setProperty('admin_emails', clean.join(','));
  return { success: true, allowlist: clean };
}

function doGet(e) {
  // API route: local uploader polls this to check for admin-queued triggers
  if (e && e.parameter && e.parameter.action === 'checkTrigger') {
    var name = e.parameter.name || '';
    countIngest_('poll');
    var result = checkAndClearTrigger(name);
    return ContentService
      .createTextOutput(JSON.stringify(result))
      .setMimeType(ContentService.MimeType.JSON);
  }

  maybeRunOneTimeInit_();
  return HtmlService.createTemplateFromFile('Index')
      .evaluate()
      .setTitle('Compliance Dashboard')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// Runs sheet setup + trigger install only once per script version, not on every page load.
// Keyed by a version string — bump the value to force a re-run after major schema changes.
var INIT_VERSION = 'v5';
function maybeRunOneTimeInit_() {
  var props = PropertiesService.getScriptProperties();
  if (props.getProperty('initDone') === INIT_VERSION) return; // already done
  ensureRegisteredDevelopersSheet();
  // v3: backfill the new roster activity columns from the legacy log sheets
  // BEFORE cleanupSheets_ deletes HeartbeatLog/ExpectedDevelopers.
  //
  // v5: this carries its own permanent guard. It is a one-shot v3 cutover, and
  // re-running it on every INIT_VERSION bump would overwrite live roster
  // activity with values re-derived from pruned log rows — and re-append rows
  // for developers who have since been purged from the roster.
  if (props.getProperty('migratedRosterActivity') !== '1') {
    try {
      migrateRosterActivity_();
      props.setProperty('migratedRosterActivity', '1');
    } catch (e) { log_('v3 migration error: ' + e.toString()); }
  }
  installPruneTrigger();
  // v5: weekly admin digests (missing reports + version drift) every Monday.
  try { ensureWeeklyDigestTrigger_(); } catch (e) { log_('v5 init: digest trigger error: ' + e.toString()); }
  // v5: weekly report window is Monday 00:00 IST → Sunday 23:59 IST.
  try { applyWeeklyGenerationDefault_(); } catch (e) { log_('v5 init: schedule error: ' + e.toString()); }
  cleanupSheets_();
  invalidateCache_();
  props.setProperty('initDone', INIT_VERSION);
}

// v3 one-time migration: derive per-developer LastSeen / LastHeartbeat /
// LastPong / LastUpload / Version / NextPollAt / LastUpdateCheck from the
// legacy ComplianceLog + HeartbeatLog rows and write them into the roster.
// Developers seen in the logs but missing from the roster are appended so
// no one disappears from the dashboard after the cutover.
function migrateRosterActivity_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ensureRegisteredDevelopersSheet();
  var userMap = {};

  function scan(sheetName, maxRows) {
    var s = ss.getSheetByName(sheetName);
    if (!s) return;
    var data = getRecentLogRows_(s, maxRows);
    for (var i = 0; i < data.length; i++) {
      var row = data[i];
      if (!row[0] || !row[1]) continue;
      var ts = row[0];
      ts = (ts && typeof ts.getTime === 'function') ? ts.toISOString() : String(ts);
      var name = String(row[1]).trim();
      if (!name) continue;
      var status = String(row[3] || '').trim().toUpperCase();
      var key = name.toLowerCase();
      if (!userMap[key]) userMap[key] = { name: name, lastSeen: '', lastHeartbeat: '', lastPong: '', lastUpload: '', version: '', nextPollAt: '', lastUpdateCheck: '' };
      var u = userMap[key];
      var isNewer = !u.lastSeen || new Date(ts) > new Date(u.lastSeen);
      if (isNewer) u.lastSeen = ts;
      if (status === 'HEARTBEAT' || status === 'WAITING' || status === 'POLLING_ACK' || status === 'PAUSED' || status === 'WAITING_PAUSED') {
        if (!u.lastHeartbeat || new Date(ts) > new Date(u.lastHeartbeat)) u.lastHeartbeat = ts;
      }
      if (status === 'PONG' && (!u.lastPong || new Date(ts) > new Date(u.lastPong))) u.lastPong = ts;
      if (status === 'SUCCESS' && (!u.lastUpload || new Date(ts) > new Date(u.lastUpload))) {
        u.lastUpload = ts;
      }
      if (row[5] && isNewer) u.nextPollAt = String(row[5]).trim();
      if (row[6] && isNewer) u.version = String(row[6]).trim();
      if (row[7] && String(row[7]).trim() !== 'never' && isNewer) u.lastUpdateCheck = String(row[7]).trim();
    }
  }
  scan('ComplianceLog', 8000);
  scan('HeartbeatLog', 2000);

  var data = sheet.getDataRange().getValues();
  var rowByKey = {};
  for (var r = 1; r < data.length; r++) {
    if (data[r][0]) rowByKey[String(data[r][0]).trim().toLowerCase()] = r + 1;
  }
  var migrated = 0;
  Object.keys(userMap).forEach(function(key) {
    var u = userMap[key];
    var rowIdx = rowByKey[key];
    if (!rowIdx) {
      sheet.appendRow([u.name, u.lastSeen || new Date().toISOString(), u.lastSeen, u.lastHeartbeat, u.lastPong, u.lastUpload, u.version, u.nextPollAt, u.lastUpdateCheck]);
    } else {
      sheet.getRange(rowIdx, 3, 1, 7).setValues([[u.lastSeen, u.lastHeartbeat, u.lastPong, u.lastUpload, u.version, u.nextPollAt, u.lastUpdateCheck]]);
    }
    migrated++;
  });
  log_('v3 migration: backfilled roster activity for ' + migrated + ' developer(s)');
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// -------------------- SHEET HELPERS --------------------

// v3: HeartbeatLog removed (noise pings now update RegisteredDevelopers
// in-place) and ExpectedDevelopers removed (roster consolidation — CSV
// reconciliation on the dashboard replaces the awaiting-onboarding list).
// cleanupSheets_() deletes both on the v3 one-time init.
var REQUIRED_SHEETS = [
  'ComplianceLog', 'RegisteredDevelopers', 'PausedDevelopers',
  'TriggerQueue', 'AppLog', 'Settings'
];

function cleanupSheets_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var obsoleteNames = ['HeartbeatLog', 'ExpectedDevelopers'];
  var removed = 0;
  obsoleteNames.forEach(function(name) {
    var s = ss.getSheetByName(name);
    if (s && ss.getSheets().length > 1) {
      try { ss.deleteSheet(s); removed++; } catch(e) {}
    }
  });
  if (removed > 0) { log_('Cleanup: removed ' + removed + ' known obsolete sheet(s)'); invalidateCache_(); }
}

// v3: the roster doubles as the live-activity database. Noise pings
// (heartbeats etc.) update these columns in-place instead of appending
// rows to a log sheet — keeps cell count flat regardless of fleet uptime.
// Columns: 1=Name 2=RegisteredAt 3=LastSeen 4=LastHeartbeat 5=LastPong
//          6=LastUpload 7=Version 8=NextPollAt 9=LastUpdateCheck
//
// v5: user-management columns (Email, System, Status, RemovedAt) are appended
// at the END rather than inserted, so every existing index-based read
// (data[i][0..8]) and the doPost cols-3–9 range write in upsertRosterActivity_
// keep working untouched. REG_CORE_HEADERS is the v4 shape and remains the
// contract that repairRegisteredDevelopersSchema_ validates — the v5 columns
// are added additively by ensureRegisteredDevelopersSheet() instead, so a
// missing Email column can never trigger the destructive legacy rewrite.
var REG_CORE_HEADERS = ['Name', 'RegisteredAt', 'LastSeen', 'LastHeartbeat', 'LastPong', 'LastUpload', 'Version', 'NextPollAt', 'LastUpdateCheck'];
var REG_USER_HEADERS = ['Email', 'System', 'Status', 'RemovedAt'];
var REG_SHEET_HEADERS = REG_CORE_HEADERS.concat(REG_USER_HEADERS);

// 0-based column offsets for the v5 user-management fields.
var REG_COL_EMAIL   = 9;
var REG_COL_SYSTEM  = 10;
var REG_COL_STATUS  = 11;
var REG_COL_REMOVED = 12;

// Lifecycle status — distinct from live presence (Online/Away/Offline), which
// is derived from heartbeat age on the client. Every user who has not been
// paused or removed reads as Active.
var USER_STATUS = { ACTIVE: 'Active', PAUSED: 'Paused', REMOVED: 'Removed' };

// Removed users keep their roster row and their Drive reports for this long so
// their historical reports stay searchable, then get purged by the daily sweep.
var REMOVED_RETENTION_DAYS = 120;

function looksLikeIsoDate_(value) {
  if (!value) return false;
  if (value && typeof value.getTime === 'function') return !isNaN(value.getTime());
  var text = String(value).trim();
  return /^\d{4}-\d{2}-\d{2}T/.test(text) && !isNaN(new Date(text).getTime());
}

function looksLikeVersion_(value) {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(String(value || '').trim());
}

function repairRegisteredDevelopersSchema_(sheet) {
  var data = sheet.getDataRange().getValues();
  if (!data.length) data = [REG_SHEET_HEADERS];
  var headers = data[0].map(function(h) { return String(h || '').trim(); });
  // v5: validate only the CORE (v4) header block. A sheet that is simply
  // missing the appended user-management columns is healthy — it gets those
  // added additively by the caller — and must not be dragged through this
  // destructive rewrite.
  var exact = headers.length >= REG_CORE_HEADERS.length;
  for (var h = 0; h < REG_CORE_HEADERS.length && exact; h++) exact = headers[h] === REG_CORE_HEADERS[h];
  if (exact) return false;

  var repaired = [REG_SHEET_HEADERS.slice()];
  for (var r = 1; r < data.length; r++) {
    var row = data[r];
    var name = String(row[0] || '').trim();
    if (!name) continue;
    // The broken v3 migration wrote activity into positions C:I while leaving
    // the old Name/FirstSeenAt/Version/Status headers in A:D. Preserve only
    // values that are valid for their intended semantic type.
    var registeredAt = looksLikeIsoDate_(row[1]) ? row[1] : new Date().toISOString();
    var lastSeen = looksLikeIsoDate_(row[2]) ? row[2] : '';
    var lastHeartbeat = looksLikeIsoDate_(row[3]) ? row[3] : '';
    var lastPong = looksLikeIsoDate_(row[4]) ? row[4] : '';
    var lastUpload = looksLikeIsoDate_(row[5]) ? row[5] : '';
    var version = looksLikeVersion_(row[6]) ? String(row[6]).trim() : (looksLikeVersion_(row[2]) ? String(row[2]).trim() : '');
    var nextPollAt = looksLikeIsoDate_(row[7]) ? row[7] : '';
    var lastUpdateCheck = looksLikeIsoDate_(row[8]) ? row[8] : '';
    // v5: carry the user-management columns through the rewrite when the sheet
    // already had them. A row with no recorded status is treated as Active.
    var email  = String(row[REG_COL_EMAIL]  || '').trim();
    var system = String(row[REG_COL_SYSTEM] || '').trim();
    var status = normalizeUserStatus_(row[REG_COL_STATUS]);
    var removedAt = looksLikeIsoDate_(row[REG_COL_REMOVED]) ? row[REG_COL_REMOVED] : '';
    repaired.push([name, registeredAt, lastSeen, lastHeartbeat, lastPong, lastUpload, version, nextPollAt, lastUpdateCheck,
                   email, system, status, removedAt]);
  }

  // Safety snapshot before the destructive rewrite — restorable directly from
  // the spreadsheet (hidden tab) without digging through Drive version history.
  try {
    var ssParent = sheet.getParent();
    var backupName = 'RegisteredDevelopers_backup_' + Utilities.formatDate(new Date(), 'UTC', 'yyyyMMdd_HHmmss');
    if (!ssParent.getSheetByName(backupName)) {
      sheet.copyTo(ssParent).setName(backupName).hideSheet();
    }
  } catch (e) {
    log_('v4 migration: pre-repair snapshot failed (continuing): ' + e);
  }

  sheet.clearContents();
  sheet.getRange(1, 1, repaired.length, REG_SHEET_HEADERS.length).setValues(repaired);
  sheet.getRange(1, 1, 1, REG_SHEET_HEADERS.length).setFontWeight('bold');
  log_('v4 migration: repaired RegisteredDevelopers header/value mapping for ' + (repaired.length - 1) + ' row(s)');
  return true;
}

function ensureRegisteredDevelopersSheet() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('RegisteredDevelopers');
  if (!sheet) {
    sheet = ss.insertSheet('RegisteredDevelopers');
    sheet.appendRow(REG_SHEET_HEADERS);
    sheet.getRange(1, 1, 1, REG_SHEET_HEADERS.length).setFontWeight('bold');
    return sheet;
  }
  if (repairRegisteredDevelopersSchema_(sheet)) return sheet;

  // v5.1: this function runs on EVERY non-throttled webhook ping, so the schema
  // check is gated behind a script-cache flag. Two reasons:
  //   1. Cost — it is pure overhead on the hot path once the schema is correct.
  //   2. Blast radius — anything that throws in here kills the roster write for
  //      the whole fleet at once (doPost swallows it and returns an error), which
  //      makes every developer read as Offline. Run it rarely and defensively.
  var cache = CacheService.getScriptCache();
  if (cache.get('reg_schema_ok_v5') === '1') return sheet;

  try {
    // getRange() past the sheet's real column count THROWS. A roster trimmed to
    // fewer than 13 columns (adminForcePrune, a manual tidy-up, or an imported
    // sheet) would otherwise take down every heartbeat. Grow it first.
    ensureRosterColumnCapacity_(sheet);

    // Additively stamp any missing header cell rather than relying on
    // getLastColumn() alone — a sheet with stray columns past the schema would
    // otherwise skip the backfill and leave Email/Status unlabelled.
    var headerRow = sheet.getRange(1, 1, 1, REG_SHEET_HEADERS.length).getValues()[0];
    var headerFixes = 0;
    for (var c = 0; c < REG_SHEET_HEADERS.length; c++) {
      if (String(headerRow[c] || '').trim() !== REG_SHEET_HEADERS[c]) headerFixes++;
    }
    if (headerFixes > 0) {
      sheet.getRange(1, 1, 1, REG_SHEET_HEADERS.length)
        .setValues([REG_SHEET_HEADERS.slice()])
        .setFontWeight('bold');
      log_('v5 schema: stamped ' + headerFixes + ' roster header cell(s)');
      // Only worth sweeping right after the v5 columns appear.
      // normalizeUserStatus_ already reads a blank cell as Active everywhere,
      // so the stored default is a cosmetic convenience, not a correctness need.
      backfillUserStatusDefaults_(sheet);
    }
    cache.put('reg_schema_ok_v5', '1', 3600); // re-verify at most hourly
  } catch (e) {
    // Never let a schema-maintenance failure break the caller. The activity
    // write in upsertRosterActivity_ only touches columns 3–9, which exist on
    // every version of this sheet, so it can safely proceed without the v5 ones.
    log_('v5 schema check failed (continuing, activity writes unaffected): ' + e.toString());
  }
  return sheet;
}

// v5.1: read-only triage for "why does the whole fleet read as Offline?".
// Run it straight from the Apps Script editor (Run ▸ diagnoseFleetPresence) and
// read the returned object in the execution log — no dashboard needed.
//
// Presence depends on LastHeartbeat/LastPong, NOT LastSeen, and the whole fleet
// freezing at the same moment means the doPost write path stopped rather than 93
// machines independently going quiet. This surfaces which of those it is.
function diagnoseFleetPresence() {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var now = Date.now();
  var buckets = { under10min: 0, under1h: 0, under6h: 0, under24h: 0, over24h: 0, never: 0 };
  var newestHeartbeatMs = 0;
  var newestSeenMs = 0;
  var total = 0;

  for (var i = 1; i < data.length; i++) {
    if (!String(data[i][0] || '').trim()) continue;
    total++;
    function ms(v) {
      if (!v) return 0;
      if (typeof v.getTime === 'function') return v.getTime();
      var t = new Date(String(v)).getTime();
      return isFinite(t) ? t : 0;
    }
    var hb = Math.max(ms(data[i][3]), ms(data[i][4])); // LastHeartbeat / LastPong
    var seen = ms(data[i][2]);
    if (hb > newestHeartbeatMs) newestHeartbeatMs = hb;
    if (seen > newestSeenMs) newestSeenMs = seen;

    if (!hb) { buckets.never++; continue; }
    var mins = (now - hb) / 60000;
    if (mins < 10)        buckets.under10min++;
    else if (mins < 60)   buckets.under1h++;
    else if (mins < 360)  buckets.under6h++;
    else if (mins < 1440) buckets.under24h++;
    else                  buckets.over24h++;
  }

  // Recent AppLog errors — schema failures and signature rejections both land here.
  var recentErrors = [];
  try {
    var appLog = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AppLog');
    if (appLog) {
      var rows = getRecentLogRows_(appLog, 300);
      for (var r = rows.length - 1; r >= 0 && recentErrors.length < 15; r--) {
        var msg = String(rows[r][1] || '');
        if (/error|failed|rejected|out of bounds|Unauthorized/i.test(msg)) {
          var ts = rows[r][0];
          if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
          recentErrors.push(String(ts) + ' — ' + msg);
        }
      }
    }
  } catch (e) {}

  var minsSinceNewest = newestHeartbeatMs ? Math.round((now - newestHeartbeatMs) / 60000) : null;
  var verdict;
  if (buckets.under10min > 0) {
    verdict = 'Webhook path is HEALTHY — ' + buckets.under10min + ' agent(s) heartbeating inside the 10-min Online window.';
  } else if (minsSinceNewest === null) {
    verdict = 'No agent has EVER recorded a heartbeat. Check that the uploader WEBHOOK_URL matches this deployment.';
  } else if (total > 5 && buckets.under1h === 0 && buckets.under6h === total - buckets.never) {
    verdict = 'ALL ' + total + ' agents last heartbeated ~' + minsSinceNewest + ' min ago and none since. ' +
              'A fleet-wide simultaneous stop means the SERVER stopped accepting writes, not that the machines slept. ' +
              'Check the Executions log for doPost failures and the errors listed below.';
  } else {
    verdict = 'Newest heartbeat is ' + minsSinceNewest + ' min old. No agent is inside the 10-min Online window.';
  }

  return {
    verdict: verdict,
    onlineThresholdMinutes: 10,
    agentHeartbeatIntervalMinutes: 5,
    rosterUsers: total,
    rosterColumns: sheet.getMaxColumns(),
    rosterColumnsRequired: REG_SHEET_HEADERS.length,
    columnCapacityOk: sheet.getMaxColumns() >= REG_SHEET_HEADERS.length,
    heartbeatAgeBuckets: buckets,
    minutesSinceNewestHeartbeat: minsSinceNewest,
    minutesSinceNewestLastSeen: newestSeenMs ? Math.round((now - newestSeenMs) / 60000) : null,
    recentErrors: recentErrors
  };
}

// Grow the sheet so every schema column physically exists. Without this,
// getRange(1, 1, 1, 13) on a 9-column sheet throws "out of bounds".
function ensureRosterColumnCapacity_(sheet) {
  var maxCols = sheet.getMaxColumns();
  if (maxCols >= REG_SHEET_HEADERS.length) return false;
  sheet.insertColumnsAfter(maxCols, REG_SHEET_HEADERS.length - maxCols);
  log_('v5 schema: grew roster from ' + maxCols + ' to ' + REG_SHEET_HEADERS.length + ' columns');
  return true;
}

// Normalize any stored status cell to one of the three known lifecycle values.
// Blank / unrecognised values mean "never explicitly set" → Active, which is
// what makes every pre-v5 developer show up as Active with no migration step.
function normalizeUserStatus_(raw) {
  var s = String(raw == null ? '' : raw).trim().toLowerCase();
  if (s === 'removed'  || s === 'deleted')  return USER_STATUS.REMOVED;
  if (s === 'paused')                       return USER_STATUS.PAUSED;
  return USER_STATUS.ACTIVE;
}

// Writes 'Active' into any blank Status cell. Idempotent and cheap: skips the
// write entirely when there is nothing to fill, so it is safe to call on every
// ensureRegisteredDevelopersSheet().
function backfillUserStatusDefaults_(sheet) {
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return;
  var range = sheet.getRange(2, REG_COL_STATUS + 1, lastRow - 1, 1);
  var values = range.getValues();
  var changed = false;
  for (var i = 0; i < values.length; i++) {
    if (String(values[i][0] || '').trim() === '') {
      // Only fill rows that actually hold a developer.
      values[i][0] = USER_STATUS.ACTIVE;
      changed = true;
    }
  }
  if (!changed) return;
  // Blank-name rows would get a stray status; mask them out first.
  var names = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
  for (var j = 0; j < values.length; j++) {
    if (String(names[j][0] || '').trim() === '') values[j][0] = '';
  }
  range.setValues(values);
  log_('v5 schema: defaulted blank roster Status cells to Active');
}

function ensurePausedDevelopersSheet_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('PausedDevelopers');
  if (!sheet) {
    sheet = ss.insertSheet('PausedDevelopers');
    sheet.appendRow(['Name', 'PausedAt', 'PausedBy']);
    sheet.getRange(1, 1, 1, 3).setFontWeight('bold');
  }
  return sheet;
}

// v2: all week-math is anchored in the script timezone (typically Asia/Kolkata
// for Sigma Solve) AND traversed via the same Utilities.formatDate call so the
// header sequence can never drift on UTC offset boundaries. Previous version
// mixed script-tz (Monday calc) with UTC (decrement) — produced off-by-one
// dates for the older entries in the 8-week grid.
function getCurrentWeekStart_() {
  var tz = Session.getScriptTimeZone();
  var nowStr = Utilities.formatDate(new Date(), tz, 'yyyy-MM-dd HH:mm:ss');
  // Reconstruct a Date that *represents* the same wall-clock time in tz
  var parts = nowStr.split(/[- :]/);
  var year = parseInt(parts[0], 10);
  var month = parseInt(parts[1], 10) - 1;
  var dayOfMonth = parseInt(parts[2], 10);
  // Day-of-week in script tz: format with EEE
  var dayName = Utilities.formatDate(new Date(), tz, 'EEE');
  var dayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  var dow = dayMap[dayName];
  var diff = (dow === 0) ? -6 : 1 - dow;
  // Build a fresh "Monday of this week, noon UTC" anchor that doesn't drift across DST
  var anchor = new Date(Date.UTC(year, month, dayOfMonth + diff, 12, 0, 0));
  return Utilities.formatDate(anchor, tz, 'yyyy-MM-dd');
}

function getWeekHeaders_(n) {
  var headers = [];
  var curr = getCurrentWeekStart_();
  var parts = curr.split('-');
  // Anchor at UTC noon to dodge DST boundary drift, then walk back 7 days at a
  // time using setUTCDate (safe arithmetic).
  var d = new Date(Date.UTC(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, parseInt(parts[2], 10), 12, 0, 0));
  for (var i = 0; i < n; i++) {
    headers.push(Utilities.formatDate(d, Session.getScriptTimeZone(), 'yyyy-MM-dd'));
    d.setUTCDate(d.getUTCDate() - 7);
  }
  return headers;
}

function ensureTriggerQueue() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('TriggerQueue');
  if (!sheet) {
    sheet = ss.insertSheet('TriggerQueue');
    sheet.appendRow(['Name', 'QueuedAt', 'QueuedBy', 'Type', 'NotBefore', 'Since', 'Until']);
    sheet.getRange(1, 1, 1, 7).setFontWeight('bold');
  } else {
    var lastCol = sheet.getLastColumn();
    if (lastCol < 4) {
      sheet.getRange(1, 4).setValue('Type').setFontWeight('bold');
    }
    if (lastCol < 5) {
      sheet.getRange(1, 5).setValue('NotBefore').setFontWeight('bold');
    }
    // v5.5: DATED_RUN carries an explicit reporting window. Added additively so
    // an existing queue keeps working untouched — every reader below defaults a
    // missing Since/Until to '' and behaves exactly as before.
    if (lastCol < 6) {
      sheet.getRange(1, 6).setValue('Since').setFontWeight('bold');
    }
    if (lastCol < 7) {
      sheet.getRange(1, 7).setValue('Until').setFontWeight('bold');
    }
  }
  return sheet;
}

// ================================================================
// v5.5 — ON-DEMAND (BACKDATED) REPORTS
// ================================================================
// Requirement: pick a person and a date, pull that period's report from THEIR
// machine, and download it from the dashboard.
//
// Verified before building (2026-07-31): Claude Code retains ~4 months of local
// session logs and does not prune them, and the bundled ccusage supports
// `--since`/`--until`, so a specific past day is genuinely recoverable rather
// than a best-effort guess. What it cannot do is invent data for a day the
// person did not use Claude — an empty result means "no usage that day".
//
// Filenames deliberately DO NOT end in _claude_daily.json / _claude_session.json.
// The weekly archive and the hourly mirror both match on that exact suffix, so
// an ad-hoc pull would otherwise be swept into the Mon–Sun weekly folders and
// corrupt the compliance record. The _ondemand_ infix keeps the two streams
// completely separate.
var ONDEMAND_FOLDER_NAME = 'On-Demand Reports';
var ONDEMAND_FILE_RE = /_claude_(daily|session)_ondemand_[0-9-]+_to_[0-9-]+\.json$/i;

// Queue a dated report pull for one developer. Their agent picks it up on its
// next poll (so the machine must be online), runs a date-scoped ccusage, and
// uploads a separately-named file.
function adminQueueDatedReport(name, sinceIso, untilIso) {
  requireAdmin_();
  name = String(name || '').trim();
  if (!name) return { success: false, error: 'Developer is required' };

  var since = String(sinceIso || '').trim();
  var until = String(untilIso || '').trim();
  if (!isIsoDateOnly_(since) || !isIsoDateOnly_(until)) {
    return { success: false, error: 'Both dates must be yyyy-MM-dd.' };
  }
  if (since > until) { var s = since; since = until; until = s; }

  // A future window can never contain data — reject rather than queue a run
  // that is guaranteed to come back empty and look like a failure.
  var todayIso = Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd');
  if (since > todayIso) {
    return { success: false, error: 'That start date is in the future (' + since + ').' };
  }

  var hit = findRosterRow_(name);
  if (!hit) return { success: false, error: name + ' is not in the roster' };
  if (normalizeUserStatus_(hit.row[REG_COL_STATUS]) === USER_STATUS.REMOVED) {
    return {
      success: false,
      error: name + ' is Removed, so their agent is paused and will never pick this up. ' +
             'Restore them first if you need a fresh pull.'
    };
  }
  if (isDeveloperPaused_(SpreadsheetApp.getActiveSpreadsheet(), name)) {
    return { success: false, error: name + ' is paused — their agent ignores triggers until resumed.' };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return { success: false, error: 'Lock timeout: the fleet is busy. Try again in a moment.' };
  }
  try {
    var sheet = ensureTriggerQueue();
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.toLowerCase()) {
        return {
          success: false,
          error: 'A trigger is already queued for ' + name +
                 '. Wait for it to run, or cancel it on the Queue & Runs page.'
        };
      }
    }
    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }
    sheet.appendRow([name, new Date().toISOString(), who, 'DATED_RUN',
                     new Date().toISOString(), since, until]);
    SpreadsheetApp.flush();
    log_('OnDemand: queued DATED_RUN for ' + name + ' (' + since + ' to ' + until + ') by ' + who);
    invalidateCache_();
    return {
      success: true, name: name, since: since, until: until,
      note: 'Queued. Their agent picks this up within ~60 seconds of its next poll, ' +
            'then generates and uploads. Refresh the list in a couple of minutes.'
    };
  } finally {
    lock.releaseLock();
  }
}

// Find-or-create the On-Demand Reports folder inside the nominated reports folder.
function ensureOnDemandFolder_() {
  var parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
  var it = parent.getFoldersByName(ONDEMAND_FOLDER_NAME);
  if (it.hasNext()) return it.next();
  var created = parent.createFolder(ONDEMAND_FOLDER_NAME);
  log_('OnDemand: created "' + ONDEMAND_FOLDER_NAME + '" folder');
  return created;
}

// Copy any on-demand files the agents have uploaded into the On-Demand Reports
// folder. Runs from the same hourly job as the live mirror, and is also called
// directly by the dashboard so a fresh pull appears without waiting an hour.
// Performance note (fixed 2026-07-31): this originally enumerated EVERY file in
// the source folder and called getName() on each to spot on-demand ones. With
// 100+ report files that is 100+ Drive round-trips per call — and because the
// dashboard called it on page load, it was heavy enough to contribute to Apps
// Script's "too many scripts running simultaneously" ceiling for something that
// usually finds nothing at all.
//
// searchFiles pushes the filtering to Drive's server side, so an empty result
// costs one query instead of a hundred calls.
function syncOnDemandReports_() {
  var out = { copied: [], skipped: [], failed: [], scanned: 0 };
  var dest;
  try { dest = ensureOnDemandFolder_(); }
  catch (e) { out.error = 'Cannot open the On-Demand folder: ' + e.toString(); return out; }

  // Only the on-demand names, resolved server-side.
  var SEARCH = 'title contains "_ondemand_"';

  var existing = {};
  try {
    var exIt = dest.searchFiles(SEARCH);
    while (exIt.hasNext()) {
      var ex = exIt.next();
      if (!ex.isTrashed()) existing[ex.getName()] = ex.getLastUpdated().getTime();
    }
  } catch (e) {
    out.error = 'Could not list existing on-demand files: ' + e.toString();
    return out;
  }

  archiveSourceFolderIds_().forEach(function(sid) {
    var src;
    try { src = DriveApp.getFolderById(sid); } catch (e) { return; }
    var it;
    try { it = src.searchFiles(SEARCH); } catch (e) { return; }
    while (it.hasNext()) {
      var f = it.next();
      if (f.isTrashed()) continue;
      var fn = f.getName();
      out.scanned++;
      // Still validate against the full pattern — `contains` is a coarse filter
      // and must not be trusted to imply the exact naming contract.
      if (!ONDEMAND_FILE_RE.test(fn)) continue;
      var upd = f.getLastUpdated().getTime();
      if (existing[fn] && upd <= existing[fn] + 1000) { out.skipped.push(fn); continue; }
      try {
        if (existing[fn]) {
          var old = dest.getFilesByName(fn);
          while (old.hasNext()) old.next().setTrashed(true);
        }
        f.makeCopy(fn, dest);
        out.copied.push(fn);
      } catch (e) {
        out.failed.push({ file: fn, error: e.toString() });
      }
    }
  });
  if (out.copied.length) log_('OnDemand: mirrored ' + out.copied.length + ' file(s)');
  return out;
}

// Everything currently available for download, newest first. Powers the
// dashboard list. Parses the window back out of the filename so the UI can show
// what period each file actually covers.
function listOnDemandReports() {
  requireAdmin_();
  // Pull anything new across before listing, so a report that finished seconds
  // ago is visible immediately rather than on the next hourly tick.
  //
  // The sync is best-effort on purpose. It is a convenience, not the source of
  // truth — if Drive is busy or the account is at its concurrent-execution
  // ceiling, the already-mirrored reports must still render rather than the
  // whole page failing with a red box.
  var synced = { copied: [] };
  var syncError = '';
  try { synced = syncOnDemandReports_(); }
  catch (e) { syncError = e.toString(); }
  if (synced && synced.error) syncError = synced.error;

  var out = [];
  try {
    var folder = ensureOnDemandFolder_();
    var it = folder.searchFiles('title contains "_ondemand_"');
    while (it.hasNext()) {
      var f = it.next();
      if (f.isTrashed()) continue;
      var fn = f.getName();
      var m = fn.match(/^(.*)_claude_(daily|session)_ondemand_([0-9-]+)_to_([0-9-]+)\.json$/i);
      if (!m) continue;
      out.push({
        fileName: fn,
        developer: m[1],
        type: m[2].toLowerCase(),
        since: m[3],
        until: m[4],
        sizeBytes: f.getSize(),
        // A 200-byte file is ccusage's empty shell — flag it so an admin is not
        // left wondering why a "successful" report contains nothing.
        looksEmpty: f.getSize() < 400,
        generatedIso: f.getLastUpdated().toISOString(),
        url: f.getUrl(),
        downloadUrl: 'https://drive.google.com/uc?export=download&id=' + f.getId()
      });
    }
  } catch (e) {
    return { error: e.toString(), reports: [] };
  }
  out.sort(function(a, b) { return b.generatedIso.localeCompare(a.generatedIso); });
  return {
    reports: out,
    count: out.length,
    justSynced: (synced && synced.copied) ? synced.copied.length : 0,
    // Surfaced as a soft warning above the list, not as a load failure.
    syncWarning: syncError || undefined
  };
}

function logQueueDatedReportExample() {
  // Edit the three values then Run, if you prefer the editor over the dashboard.
  Logger.log(JSON.stringify(
    adminQueueDatedReport('Hitarth_Desai', '2026-06-08', '2026-06-08'), null, 2));
}

// The on-demand list now relies on Drive-side search instead of enumerating the
// folder. DriveApp search has historically been less predictable inside Shared
// Drives, so this proves it works here rather than assuming: it compares a
// search for a pattern KNOWN to exist against a plain enumeration of the same
// folder. If searchMatches is 0 while enumerationMatches is not, the search is
// not honoured on this drive and syncOnDemandReports_ must go back to scanning.
function logVerifyDriveSearch() {
  var out = { folders: [] };
  archiveSourceFolderIds_().forEach(function(sid) {
    var row = { folderId: sid };
    try {
      var src = DriveApp.getFolderById(sid);
      row.folderName = src.getName();

      var s = 0, it = src.searchFiles('title contains "_claude_daily"');
      while (it.hasNext()) { it.next(); s++; }
      row.searchMatches = s;

      var e = 0, total = 0, it2 = src.getFiles();
      while (it2.hasNext()) {
        total++;
        if (it2.next().getName().indexOf('_claude_daily') !== -1) e++;
      }
      row.enumerationMatches = e;
      row.totalFilesInFolder = total;
      row.searchWorks = (s === e);
      row.callsSaved = total - s;

      var od = 0, it3 = src.searchFiles('title contains "_ondemand_"');
      while (it3.hasNext()) { it3.next(); od++; }
      row.onDemandFilesPresent = od;
    } catch (err) {
      row.error = err.toString();
    }
    out.folders.push(row);
  });
  Logger.log(JSON.stringify(out, null, 2));
}

function logOnDemandReports() {
  Logger.log(JSON.stringify(listOnDemandReports(), null, 2));
}

// -------------------- TRIGGER QUEUE --------------------

function adminQueueTrigger(name, type) {
  requireAdmin_();
  type = type || 'FORCE_RUN';
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var sheet = ensureTriggerQueue();

    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.trim().toLowerCase()) {
        return { success: false, error: 'A trigger is already queued for ' + name };
      }
    }

    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }

    sheet.appendRow([name.trim(), new Date().toISOString(), who, type, new Date().toISOString()]);
    log_('TriggerQueue: queued ' + type + ' for ' + name + ' by ' + who);
    invalidateCache_();
    return { success: true };
  } finally {
    lock.releaseLock();
  }
}

// Bulk-queue triggers for multiple developers in ONE lock acquisition.
// Skips names already in the queue. Returns { queued: [], skipped: [] }.
//
// `type` defaults to FORCE_RUN for the original caller (bulk force-run). Also
// used for bulk UPDATE (Version Matrix "Force update N outdated") — see the
// 2026-07-30 fix note on forceSendUpdateBatch: that endpoint used to call
// adminQueueTrigger() once PER developer, meaning a 26-person bulk update took
// the whole-script lock 26 separate times. With ~20 agents heartbeating
// concurrently (each heartbeat briefly takes the same lock for its own
// smart-retry/auto-generate check), that many individual acquisitions reliably
// produced "Lock timeout" failures partway through a bulk operation. One
// acquisition for the entire batch removes 25 of those 26 contention points.
function adminQueueTriggerBatch(names, type) {
  requireAdmin_();
  type = type || 'FORCE_RUN';
  if (!names || !names.length) return { queued: [], skipped: [] };
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var sheet = ensureTriggerQueue();
    var data = sheet.getDataRange().getValues();
    var alreadyQueued = {};
    for (var i = 1; i < data.length; i++) {
      if (data[i][0]) alreadyQueued[String(data[i][0]).trim().toLowerCase()] = true;
    }
    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }
    var queued = [], skipped = [], baseTime = Date.now();
    names.forEach(function(name) {
      var key = String(name).trim().toLowerCase();
      if (alreadyQueued[key]) {
        skipped.push(name);
      } else {
        // Stagger 60s apart — for FORCE_RUN this avoids simultaneous GAS
        // executions; for UPDATE it avoids a stampede of ~72MB downloads and
        // Drive/GAS calls all firing in the same instant.
        var notBefore = new Date(baseTime + queued.length * 60000).toISOString();
        sheet.appendRow([name.trim(), new Date().toISOString(), who, type, notBefore]);
        queued.push(name);
        alreadyQueued[key] = true;
      }
    });
    if (queued.length > 0) {
      log_('TriggerQueue: batch queued ' + queued.length + ' ' + type + '(s) by ' + who);
      invalidateCache_();
    }
    return { queued: queued, skipped: skipped };
  } finally {
    lock.releaseLock();
  }
}

// Queue a ping request — uploader responds with PONG status
function adminQueuePing(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var sheet = ensureTriggerQueue();

    // Replace any existing queue entry for this user (ping supersedes nothing, but prevent dupe)
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.trim().toLowerCase()) {
        // If already a PING pending, don't add another
        if (String(data[i][3]).trim() === 'PING') {
          return { success: false, error: 'Ping already pending for ' + name };
        }
        // If a FORCE_RUN is pending, let it be — just add the ping on top (different rows)
      }
    }

    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }

    sheet.appendRow([name.trim(), new Date().toISOString(), who, 'PING', new Date().toISOString()]);
    log_('TriggerQueue: queued PING for ' + name + ' by ' + who);
    invalidateCache_();
    return { success: true };
  } finally {
    lock.releaseLock();
  }
}

// v2.0.7: the Drive upload folder the fleet should write to.
//
// Empty (the default) means "use the folder compiled into the binary", which is
// the safe state: it cannot break anything. Setting it makes every v2.0.7+ agent
// switch on its next poll — within 60 seconds, no rebuild, no desk visits.
// Pre-v2.0.7 agents simply ignore the extra field.
var UPLOAD_FOLDER_SETTING_KEY = 'uploadDriveFolderId';

function getUploadDriveFolderIdCached_() {
  // Same 10-minute settings cache as uploadFrequency — this is read on every
  // poll by every agent, so it must never hit the spreadsheet in the hot path.
  return getSettingCached_(UPLOAD_FOLDER_SETTING_KEY, '');
}

// Point the fleet at a different Drive folder. Validates before saving, because
// a bad value here propagates to every machine within a minute.
function setUploadDriveFolderId(folderId) {
  requireAdmin_();
  var id = String(folderId == null ? '' : folderId).trim();

  // Accept a pasted Drive URL as well as a bare ID — the URL is what an admin
  // actually has in their clipboard, and silently mis-saving it would break uploads.
  var m = id.match(/\/folders\/([A-Za-z0-9_-]{10,80})/);
  if (m) id = m[1];

  if (id && !/^[A-Za-z0-9_-]{10,80}$/.test(id)) {
    return { success: false, error: 'That does not look like a Drive folder ID or URL: ' + folderId };
  }

  // Empty = revert the fleet to the compiled default. Always allowed.
  if (id) {
    // Confirm the folder at least EXISTS and this script can see it. Note the
    // caveat below: this proves nothing about the service account the agents use.
    try {
      var f = DriveApp.getFolderById(id);
      var probeName = f.getName();
    } catch (e) {
      return {
        success: false,
        error: 'Cannot open that folder as this script: ' + e.toString(),
        hint: 'Check the ID, and make sure the folder is shared with the Apps Script owner account.'
      };
    }
  }

  var sheet = ensureSettingsSheet_();
  setSettingValue_(sheet, UPLOAD_FOLDER_SETTING_KEY, id);
  invalidateCache_();
  log_('Fleet upload folder set to: ' + (id || '(compiled default)'));

  return {
    success: true,
    folderId: id,
    usingCompiledDefault: !id,
    folderName: id ? probeName : null,
    rolloutNote: 'Every v2.0.7+ agent switches on its next poll (<=60s). Agents on ' +
                 'v2.0.6 or earlier ignore this and keep using their compiled folder ' +
                 'until they self-update.',
    criticalCaveat: 'The AGENTS authenticate as the SERVICE ACCOUNT (' +
                    'see service-account-key.json), NOT as this script. This check only ' +
                    'proved the script can see the folder. Grant the service account ' +
                    'Editor on it too, or every upload will 404 and fall back to the old folder.'
  };
}

function getUploadDriveFolderInfo() {
  requireAdmin_();
  var id = getSetting_(UPLOAD_FOLDER_SETTING_KEY, '');
  var out = { folderId: id, usingCompiledDefault: !id, compiledDefault: SHARED_DRIVE_FOLDER_ID };
  if (id) {
    try { out.folderName = DriveApp.getFolderById(id).getName(); }
    catch (e) { out.folderName = null; out.warning = 'Script cannot open this folder: ' + e.toString(); }
  }
  return out;
}

// ---------- FLEET UPLOAD FOLDER: ONE-CLICK OPERATIONS ----------
// The Apps Script editor cannot pass arguments to a Run, so setUploadDriveFolderId
// is unreachable from the UI on its own. Edit the constant below, then run the
// wrappers in order:
//   1. logPreflightUploadFolder   — is it safe? (does NOT change anything)
//   2. logSetFleetUploadFolder    — switch the fleet over
//   3. logUploadFolderInfo        — confirm what is live
//   4. logRevertFleetUploadFolder — undo, back to the compiled folder
var SETUP_FLEET_UPLOAD_FOLDER = '1ss0gkNQPjFRoqRLp2zmGV7SEUp5tbzVu';

// The identity the AGENTS use for Drive — from service-account-key.json, which
// ships beside each executable. This script runs as a completely different
// account, which is why "the dashboard can see the folder" proves nothing about
// whether uploads will work. Checked explicitly in the preflight below.
var UPLOADER_SERVICE_ACCOUNT_EMAIL = 'claude-uploader@claude-usage-auto-uploader.iam.gserviceaccount.com';

// Read-only. Answers the only question that matters before switching: will the
// agents actually be able to write there? Changes nothing.
function preflightUploadFolder(folderId) {
  requireAdmin_();
  var id = String(folderId || SETUP_FLEET_UPLOAD_FOLDER || '').trim();
  var m = id.match(/\/folders\/([A-Za-z0-9_-]{10,80})/);
  if (m) id = m[1];
  var out = { folderId: id, serviceAccount: UPLOADER_SERVICE_ACCOUNT_EMAIL, blockers: [], warnings: [] };

  if (!/^[A-Za-z0-9_-]{10,80}$/.test(id)) {
    out.blockers.push('"' + id + '" is not a Drive folder ID or URL.');
    out.verdict = 'BLOCKED. ' + out.blockers[0];
    return out;
  }

  var folder;
  try {
    folder = DriveApp.getFolderById(id);
    out.folderName = folder.getName();
    out.scriptCanRead = true;
  } catch (e) {
    out.scriptCanRead = false;
    out.blockers.push('This script cannot open the folder: ' + e.toString());
    out.verdict = 'BLOCKED. The dashboard cannot see this folder, so it could never archive from it.';
    return out;
  }

  // Can THIS script write? Needed for the weekly archive, not for the uploads.
  try {
    var probe = folder.createFolder('__preflight_probe_' +
      Utilities.formatDate(new Date(), 'UTC', 'yyyyMMdd_HHmmss'));
    probe.setTrashed(true);
    out.scriptCanWrite = true;
  } catch (e) {
    out.scriptCanWrite = false;
    out.warnings.push('This script cannot WRITE here, so weekly dated folders could not be created ' +
                      'inside it. Uploads may still work — these are different accounts.');
  }

  // THE decisive check: is the agents' service account actually an editor?
  // Direct sharing shows up in getEditors(); access inherited from a shared-drive
  // membership does not, so a negative result is "unproven", never "definitely broken".
  out.serviceAccountIsEditor = null;
  try {
    var emails = folder.getEditors().map(function(u) { return String(u.getEmail() || '').toLowerCase(); });
    var owner = '';
    try { owner = String(folder.getOwner().getEmail() || '').toLowerCase(); } catch (e2) {}
    if (owner) emails.push(owner);
    out.editorsVisible = emails.length;
    out.serviceAccountIsEditor = emails.indexOf(UPLOADER_SERVICE_ACCOUNT_EMAIL.toLowerCase()) !== -1;
    if (!out.serviceAccountIsEditor) {
      out.blockers.push('The uploader service account is NOT listed as an editor on this folder. ' +
        'Share the folder with ' + UPLOADER_SERVICE_ACCOUNT_EMAIL + ' as Editor first, or every ' +
        'upload will fail with 404 and each agent will silently fall back to the old folder.');
    }
  } catch (e) {
    out.warnings.push('Could not list the folder permissions (' + e.toString() + '), so the ' +
                      'service account access is UNVERIFIED. Confirm it manually in Drive > Share.');
  }

  out.verdict = out.blockers.length === 0
    ? (out.warnings.length === 0
        ? 'READY. ' + UPLOADER_SERVICE_ACCOUNT_EMAIL + ' can write to "' + out.folderName +
          '". Run logSetFleetUploadFolder to switch the fleet.'
        : 'READY WITH WARNINGS — read them, then run logSetFleetUploadFolder.')
    : 'NOT READY. ' + out.blockers[0];
  return out;
}

function logPreflightUploadFolder() {
  Logger.log(JSON.stringify(preflightUploadFolder(), null, 2));
}

// Switches every v2.0.7+ agent to SETUP_FLEET_UPLOAD_FOLDER on its next poll.
// Refuses to run if the preflight found a hard blocker — a wrong value here
// reaches the whole fleet within a minute.
function logSetFleetUploadFolder() {
  var pre = preflightUploadFolder();
  if (pre.blockers && pre.blockers.length > 0) {
    Logger.log(JSON.stringify({
      aborted: true,
      reason: 'Preflight found blocker(s) — nothing was changed.',
      blockers: pre.blockers,
      preflight: pre
    }, null, 2));
    return;
  }
  var result = setUploadDriveFolderId(SETUP_FLEET_UPLOAD_FOLDER);
  // setUploadDriveFolderId carries a standing warning that it cannot verify the
  // service account — true when called directly, but the preflight above just
  // verified exactly that. Leaving the warning in place next to a
  // serviceAccountIsEditor:true reads as "you still have work to do", so resolve it.
  if (pre.serviceAccountIsEditor === true) {
    result.criticalCaveat = 'RESOLVED by preflight: ' + UPLOADER_SERVICE_ACCOUNT_EMAIL +
      ' is confirmed as an editor on this folder, so agent uploads will not 404.';
  } else if (pre.serviceAccountIsEditor === null) {
    result.criticalCaveat = 'UNVERIFIED: the folder permissions could not be listed, so it is ' +
      'still unproven that ' + UPLOADER_SERVICE_ACCOUNT_EMAIL + ' can write here. If uploads ' +
      'start failing, each agent logs CRITICAL and falls back to its compiled folder — ' +
      'reports keep arriving, in the old location.';
  }
  result.preflight = pre;
  Logger.log(JSON.stringify(result, null, 2));
}

function logUploadFolderInfo() {
  Logger.log(JSON.stringify(getUploadDriveFolderInfo(), null, 2));
}

// After switching the fleet upload folder, the question is always the same:
// are uploads landing in the new place, failing, or quietly still going to the
// old one? The agents report the answer in their FAILURE messages, but those are
// buried in ComplianceLog. This pulls them out verbatim.
//
// Reads only — safe to run any time.
function diagnoseRecentUploads(hoursBack) {
  requireAdmin_();
  var hours = parseInt(hoursBack, 10);
  if (!isFinite(hours) || hours <= 0 || hours > 168) hours = 24;
  var cutoff = Date.now() - hours * 3600000;

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('ComplianceLog');
  var out = {
    windowHours: hours,
    configuredUploadFolder: getSetting_(UPLOAD_FOLDER_SETTING_KEY, '') || '(compiled default)',
    compiledDefaultFolder: SHARED_DRIVE_FOLDER_ID,
    statusCounts: {},
    failures: [],
    successes: [],
    distinctErrorKinds: {}
  };
  if (!sheet) { out.error = 'No ComplianceLog sheet.'; return out; }

  var rows = getRecentLogRows_(sheet, 3000);
  for (var i = rows.length - 1; i >= 0; i--) {
    var ts = rows[i][0];
    var tms = (ts && typeof ts.getTime === 'function') ? ts.getTime() : new Date(String(ts)).getTime();
    if (!isFinite(tms) || tms < cutoff) continue;

    var status = String(rows[i][3] || '').trim().toUpperCase();
    var name   = String(rows[i][1] || '').trim();
    var msg    = String(rows[i][4] || '');
    out.statusCounts[status] = (out.statusCounts[status] || 0) + 1;

    if (status === 'FAILURE' && out.failures.length < 25) {
      out.failures.push({ name: name, at: new Date(tms).toISOString(), message: msg.substring(0, 300) });
      // Group by the error CODE the client emits (DRIVE_UPLOAD_FAILED etc.) plus
      // the Drive reason, so one glance shows whether it is one fault or many.
      var kind = (msg.match(/[A-Z][A-Z_]{6,}/) || ['UNCLASSIFIED'])[0];
      var reason = (msg.match(/storageQuotaExceeded|insufficientFilePermissions|insufficientPermissions|notFound|File not found|forbidden|401|403|404|429/i) || [''])[0];
      var key = kind + (reason ? ' / ' + reason : '');
      out.distinctErrorKinds[key] = (out.distinctErrorKinds[key] || 0) + 1;
    }
    if (status === 'SUCCESS' && out.successes.length < 15) {
      out.successes.push({ name: name, at: new Date(tms).toISOString(), message: msg.substring(0, 200) });
    }
  }

  // The decisive interpretation, spelled out so it does not need decoding.
  var quota = 0;
  Object.keys(out.distinctErrorKinds).forEach(function(k) {
    if (/storageQuotaExceeded/i.test(k)) quota += out.distinctErrorKinds[k];
  });
  if (quota > 0) {
    out.verdict = 'STORAGE QUOTA FAILURE (' + quota + ' occurrence(s)). The service account has no ' +
      'Drive storage of its own, so it CANNOT create files in an ordinary My Drive folder — only in a ' +
      'Shared Drive, where the drive owns the files. The configured upload folder must be moved into a ' +
      'Shared Drive, or the fleet pointed back at the compiled default.';
  } else if ((out.statusCounts.SUCCESS || 0) > 0 && (out.statusCounts.FAILURE || 0) === 0) {
    out.verdict = 'Uploads are SUCCEEDING (' + out.statusCounts.SUCCESS + ' in the last ' + hours +
      'h) with no failures. If the new folder still looks empty, the agents are writing to the OLD ' +
      'folder — meaning they have not applied the new setting yet (check their reported version is 2.0.7 ' +
      'and that they have polled since the change).';
  } else if ((out.statusCounts.FAILURE || 0) > 0) {
    out.verdict = out.statusCounts.FAILURE + ' failure(s) in the last ' + hours +
      'h. Read distinctErrorKinds and failures[].message below — the Drive reason string names the cause.';
  } else {
    out.verdict = 'No SUCCESS or FAILURE rows in this window. Widen it: diagnoseRecentUploads(72).';
  }
  return out;
}

function logRecentUploads() {
  Logger.log(JSON.stringify(diagnoseRecentUploads(24), null, 2));
}

// Undo: clears the setting so every agent returns to the folder compiled into
// its binary. Takes effect on the next poll.
function logRevertFleetUploadFolder() {
  Logger.log(JSON.stringify(setUploadDriveFolderId(''), null, 2));
}

function checkAndClearTrigger(name) {
  if (!name) return { triggered: false, paused: false };

  // --- FAST PATH: serve all three pre-checks from CacheService.
  // 99% of calls (idle developers) take this branch with ZERO spreadsheet reads.
  var pausedSet       = getPausedSetCached_();
  var uploadFrequency = getSettingCached_('uploadFrequency', 'weekly');
  var uploadSchedule  = getUploadScheduleCached_();
  var driveFolderId   = getUploadDriveFolderIdCached_();
  var paused          = !!pausedSet[name.trim().toLowerCase()];

  // Trigger-queue check — served from a 15-second cache.
  // Only a real trigger event (very rare) causes a cache miss here.
  var queueRows = getTriggerQueueRowsCached_();
  var now = new Date();
  var candidateFound = false;
  var nameLower = name.trim().toLowerCase();
  for (var k = 0; k < queueRows.length; k++) {
    if (queueRows[k].name.toLowerCase() === nameLower) {
      var nb = queueRows[k].notBefore;
      if (nb && new Date(nb) > now) continue; // not yet ready
      candidateFound = true;
      break;
    }
  }
  if (!candidateFound) {
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule, driveFolderId: driveFolderId };
  }

  // --- SAFE PATH (exclusive lock) ---
  // A row was spotted in cache; acquire the lock and re-read from the sheet before
  // mutating so concurrent requests cannot double-consume the same trigger entry.
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var qSheet = ss.getSheetByName('TriggerQueue');
  if (!qSheet) return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule, driveFolderId: driveFolderId };

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) {
    log_('checkAndClearTrigger: lock timeout for ' + name);
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule, driveFolderId: driveFolderId };
  }
  try {
    var data = qSheet.getDataRange().getValues();
    var now2 = new Date();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === nameLower) {
        var nb2 = data[i][4] ? String(data[i][4]).trim() : '';
        if (nb2 && new Date(nb2) > now2) continue; // not yet ready
        var triggerType = data[i][3] ? String(data[i][3]).trim() : 'FORCE_RUN';
        // v5.5: DATED_RUN carries the reporting window in cols 6/7. Sent as
        // `since`/`until` so the agent can scope ccusage to that exact period.
        var since = data[i][5] ? String(data[i][5]).trim() : '';
        var until = data[i][6] ? String(data[i][6]).trim() : '';
        qSheet.deleteRow(i + 1);
        SpreadsheetApp.flush();  // commit immediately so concurrent readers see it gone
        log_('TriggerQueue: consumed ' + triggerType + ' for ' + name +
             (since ? ' (' + since + ' to ' + until + ')' : ''));
        invalidateCache_();
        return { triggered: true, type: triggerType, since: since, until: until,
                 paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule, driveFolderId: driveFolderId };
      }
    }
    // Trigger was claimed by a concurrent request between the cache-check and lock acquisition.
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule, driveFolderId: driveFolderId };
  } finally {
    lock.releaseLock();
  }
}

function adminGetTriggerQueue() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('TriggerQueue');
  if (!sheet) return [];

  var data = sheet.getDataRange().getValues();
  var result = [];
  for (var i = 1; i < data.length; i++) {
    if (data[i][0]) {
      result.push({
        name: String(data[i][0]).trim(),
        queuedAt: data[i][1] ? String(data[i][1]) : '',
        queuedBy: data[i][2] ? String(data[i][2]) : '',
        type: data[i][3] ? String(data[i][3]).trim() : 'FORCE_RUN',
        notBefore: data[i][4] ? String(data[i][4]).trim() : ''
      });
    }
  }
  return result;
}

function adminCancelTrigger(name) {
  requireAdmin_();
  if (!name) return { success: false };
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('TriggerQueue');
    if (!sheet) return { success: false };

    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.trim().toLowerCase()) {
        sheet.deleteRow(i + 1);
        invalidateCache_();
        return { success: true };
      }
    }
    return { success: false, error: 'No trigger found for ' + name };
  } finally {
    lock.releaseLock();
  }
}

// Wipes every queued trigger in one shot. Useful to clear stale rows that were
// never consumed because the agent was offline when the trigger was issued.
function adminClearAllTriggers() {
  requireAdmin_();
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('TriggerQueue');
    if (!sheet) return { success: true, cleared: 0 };

    var lastRow = sheet.getLastRow();
    if (lastRow <= 1) return { success: true, cleared: 0 };  // header only

    var numRows = lastRow - 1;
    sheet.deleteRows(2, numRows);  // delete all data rows in one API call
    SpreadsheetApp.flush();
    log_('TriggerQueue: cleared ' + numRows + ' stale trigger(s)');
    invalidateCache_();
    return { success: true, cleared: numRows };
  } finally {
    lock.releaseLock();
  }
}

// -------------------- DEVELOPER LOGS --------------------

// Returns the last `limit` log entries for a specific developer, newest first.
function getDeveloperLogs(name, limit) {
  requireAdmin_(); // v2: gate behind admin allowlist (soft — no-op in pilot mode)
  limit = limit || 25;
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var logs = [];
  
  function extractLogs(sheetName) {
    var logSheet = ss.getSheetByName(sheetName);
    if (!logSheet) return;
    var data = getRecentLogRows_(logSheet, 300);
    for (var i = data.length - 1; i >= 0; i--) {
      var row = data[i];
      if (!row[0]) continue;
      if (String(row[1]).trim().toLowerCase() !== name.trim().toLowerCase()) continue;

      var ts = row[0];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
      else ts = String(ts);

      logs.push({
        timestamp: ts,
        status: String(row[3]).trim().toUpperCase(),
        message: String(row[4] || '')
      });
    }
  }

  // v3: ComplianceLog only — heartbeat noise no longer produces log rows
  // (live presence is shown from the roster instead).
  extractLogs('ComplianceLog');

  // Sort by timestamp descending (newest first)
  logs.sort(function(a, b) {
    return new Date(b.timestamp) - new Date(a.timestamp);
  });

  return logs.slice(0, limit);
}

// -------------------- ACTIVE USERS --------------------

// v3: reads per-developer activity straight from the RegisteredDevelopers
// roster (kept current in-place by doPost) — no log scanning. One sheet read
// of N rows replaces the old 2000-row ComplianceLog/HeartbeatLog sweep.
// Returns array of { name, lastSeen, lastHeartbeat, lastUpload, lastPong, ... }
function getActiveUsers() {
  requireAdmin_(); // v2: gate behind admin allowlist (soft — no-op in pilot mode)
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureRegisteredDevelopersSheet();
  var sheet = ss.getSheetByName('RegisteredDevelopers');
  if (!sheet) return [];
  var data = sheet.getDataRange().getValues();

  function isoStr(v) {
    if (!v) return null;
    if (typeof v.getTime === 'function') return v.toISOString();
    var s = String(v).trim();
    return s || null;
  }

  // Enrich with pending trigger info
  var triggerMap = {};
  var tSheet = ss.getSheetByName('TriggerQueue');
  if (tSheet) {
    var tData = tSheet.getDataRange().getValues();
    for (var j = 1; j < tData.length; j++) {
      if (tData[j][0]) {
        var tName = String(tData[j][0]).trim().toLowerCase();
        var tType = tData[j][3] ? String(tData[j][3]).trim() : 'FORCE_RUN';
        if (!triggerMap[tName]) triggerMap[tName] = {};
        triggerMap[tName][tType] = true;
      }
    }
  }

  // Check paused state for all users
  var pausedMap = getPausedDevelopersMap_();

  var users = [];
  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    var key = name.toLowerCase();
    var isPaused = !!pausedMap[key];
    var storedStatus = normalizeUserStatus_(data[i][REG_COL_STATUS]);
    // Pause state lives in its own sheet and is the authority for the Paused
    // label; the Status cell only distinguishes Removed from everything else.
    var status = storedStatus === USER_STATUS.REMOVED
      ? USER_STATUS.REMOVED
      : (isPaused ? USER_STATUS.PAUSED : USER_STATUS.ACTIVE);
    var removedAt = isoStr(data[i][REG_COL_REMOVED]);
    users.push({
      name: name,
      registeredAt:        isoStr(data[i][1]),
      lastSeen:            isoStr(data[i][2]),
      lastHeartbeat:       isoStr(data[i][3]),
      lastPong:            isoStr(data[i][4]),
      lastUpload:          isoStr(data[i][5]),
      version:             data[i][6] ? String(data[i][6]).trim() : null,
      lastSuccessNextPoll: isoStr(data[i][7]),  // NextPollAt — feeds the Upload Summary "Next Up" cell
      lastUpdateCheck:     data[i][8] ? String(data[i][8]).trim() : null,
      email:          data[i][REG_COL_EMAIL]  ? String(data[i][REG_COL_EMAIL]).trim()  : '',
      system:         data[i][REG_COL_SYSTEM] ? String(data[i][REG_COL_SYSTEM]).trim() : '',
      status:         status,
      removedAt:      removedAt,
      retentionDaysLeft: status === USER_STATUS.REMOVED ? removedRetentionDaysLeft_(removedAt) : null,
      pendingTrigger: !!(triggerMap[key] && triggerMap[key]['FORCE_RUN']),
      pendingPing:    !!(triggerMap[key] && triggerMap[key]['PING']),
      paused:         isPaused,
      pausedAt:       pausedMap[key] ? pausedMap[key].pausedAt : null,
      pausedBy:       pausedMap[key] ? pausedMap[key].pausedBy : null
    });
  }
  return users.sort(function(a, b) {
    if (!a.lastSeen) return 1;
    if (!b.lastSeen) return -1;
    return new Date(b.lastSeen) - new Date(a.lastSeen);
  });
}

// -------------------- DASHBOARD DATA --------------------

// v2: full flush — used by admin mutations only (queueing triggers, paused
// state changes, settings edits, roster edits). Heavy and expensive.
function invalidateCache_() {
  var c = CacheService.getScriptCache();
  chunkedCacheRemove(c, 'dashboardData');
  c.remove('pausedSet');
  c.remove('triggerQueueRows');
  c.remove('setting_uploadFrequency');
  c.remove('upload_schedule_json');
  c.remove('latest_uploader_version_gist');
  c.put('lastModified', String(Date.now()), 3600);
}

// v2: light flush — used by the webhook path on every ComplianceLog /
// HeartbeatLog append. Only invalidates the dashboard payload itself; the
// trigger-queue cache is left alone because heartbeat writes never mutate it,
// and at fleet scale (50 devs × 12 pings/hr = 600 writes/hr) the previous
// behaviour effectively disabled trigger-queue caching.
function bumpLastModified_() {
  try {
    var c = CacheService.getScriptCache();
    chunkedCacheRemove(c, 'dashboardData');
    c.put('lastModified', String(Date.now()), 3600);
  } catch (e) { /* fail-open */ }
}

// -------------------- CACHED FAST-READ HELPERS --------------------
// These replace direct sheet reads in the hot path (checkAndClearTrigger).
// Every mutation calls invalidateCache_() which flushes these keys immediately.

var CACHE_TTL_SETTINGS     = 600;  // settings change rarely — 10 min
var CACHE_TTL_PAUSED       = 120;  // paused state — 2 min
// Trigger queue. Freshness comes from invalidateCache_(), which every queueing
// path calls the moment a trigger is written — NOT from this TTL. The TTL is a
// safety net for the rare case where invalidation fails, so it does not need to
// be aggressive. It used to be 15s, which was shorter than the 60s agent poll
// interval and therefore guaranteed a cache miss on *every* poll from *every*
// agent — 22 spreadsheet reads a minute for data that had not changed.
var CACHE_TTL_TRIGGERQUEUE = 60;

// ---------------------------------------------------------------------------
// Lock policy for the three getters below (changed 2026-07-31)
//
// These used to take the shared script lock before populating their cache, to
// stop several executions computing the same value at once. That was a bad
// trade. Populating a cache is IDEMPOTENT — if two executions both read the
// sheet and both write the same value, the result is identical and no data is
// harmed. The only thing the lock bought was avoiding a duplicate read.
//
// What it cost was severe: every agent poll passes through here, so 22 agents
// churned the one global script lock continuously. Genuine mutations that
// legitimately need exclusivity — deleting a user, claiming a trigger — then
// could not get it, and surfaced to the admin as
// "Lock timeout: another process was holding the lock for too long".
//
// So: no lock on read/populate paths. The lock is now reserved for actual
// mutations. A redundant sheet read is cheap; a starved mutation is not.
// ---------------------------------------------------------------------------

function getSettingCached_(key, defaultVal) {
  var c = CacheService.getScriptCache();
  var cacheKey = 'setting_' + key;
  var cached = c.get(cacheKey);
  if (cached !== null) return cached;

  var val = getSetting_(key, defaultVal);
  try { c.put(cacheKey, String(val), CACHE_TTL_SETTINGS); } catch (e) {}
  return val;
}

// Returns a plain set {lowerCaseName: true} for O(1) lookup.
function getPausedSetCached_() {
  var c = CacheService.getScriptCache();
  var cached = c.get('pausedSet');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch(e) {}
  }

  var map = getPausedDevelopersMap_();
  var set = {};
  Object.keys(map).forEach(function(k) { set[k] = true; });
  try { c.put('pausedSet', JSON.stringify(set), CACHE_TTL_PAUSED); } catch(e) {}
  return set;
}

// Returns serialised trigger-queue rows so doGet/checkAndClearTrigger
// can check for pending triggers without opening the spreadsheet at all.
function getTriggerQueueRowsCached_() {
  var c = CacheService.getScriptCache();
  var cached = c.get('triggerQueueRows');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch(e) {}
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('TriggerQueue');
  if (!sheet) {
    try { c.put('triggerQueueRows', '[]', CACHE_TTL_TRIGGERQUEUE); } catch(e) {}
    return [];
  }
  var data = sheet.getDataRange().getValues();
  var rows = [];
  for (var i = 1; i < data.length; i++) {
    if (data[i][0]) rows.push({
      name:      String(data[i][0]).trim(),
      type:      data[i][3] ? String(data[i][3]).trim() : 'FORCE_RUN',
      notBefore: data[i][4] ? String(data[i][4]).trim() : ''
    });
  }
  try { c.put('triggerQueueRows', JSON.stringify(rows), CACHE_TTL_TRIGGERQUEUE); } catch(e) {}
  return rows;
}

// Lightweight endpoint — returns only a change timestamp.
// The dashboard polls this every 5s so new registrations surface immediately
// without doing a full getDashboardData fetch every 5s.
function getLastModified() {
  var ts = CacheService.getScriptCache().get('lastModified');
  return { ts: ts ? parseInt(ts, 10) : 0 };
}

function chunkedCachePut(cache, key, stringData, expiration) {
  var MAX_CHUNK_SIZE = 50000;
  var chunks = Math.ceil(stringData.length / MAX_CHUNK_SIZE);
  if (chunks > 1) {
    for (var i = 0; i < chunks; i++) {
      cache.put(key + '_chunk_' + i, stringData.substring(i * MAX_CHUNK_SIZE, (i + 1) * MAX_CHUNK_SIZE), expiration);
    }
    cache.put(key + '_chunks', String(chunks), expiration);
  } else {
    cache.put(key, stringData, expiration);
    cache.remove(key + '_chunks');
  }
}

function chunkedCacheGet(cache, key) {
  var chunksStr = cache.get(key + '_chunks');
  if (chunksStr) {
    var numChunks = parseInt(chunksStr, 10);
    var data = '';
    for (var i = 0; i < numChunks; i++) {
      var chunk = cache.get(key + '_chunk_' + i);
      if (!chunk) return null; // Incomplete
      data += chunk;
    }
    return data;
  }
  return cache.get(key);
}

function chunkedCacheRemove(cache, key) {
  var chunksStr = cache.get(key + '_chunks');
  if (chunksStr) {
    var numChunks = parseInt(chunksStr, 10);
    for (var i = 0; i < numChunks; i++) {
      cache.remove(key + '_chunk_' + i);
    }
    cache.remove(key + '_chunks');
  }
  cache.remove(key);
}

function getDashboardData() {
  requireAdmin_(); // v2: gate behind admin allowlist (soft — no-op in pilot mode)
  var cache = CacheService.getScriptCache();
  var cached = chunkedCacheGet(cache, 'dashboardData');
  if (cached) {
    try { return JSON.parse(cached); } catch(e) {}
  }
  
  // The lock here is a de-duplication nicety, not a correctness requirement:
  // getDashboardData_uncached_ is strictly read-only (verified — no setValue /
  // appendRow / setProperty anywhere in it), so two executions computing it
  // concurrently produce the same answer and harm nothing.
  //
  // It used to waitLock(10000) and THROW on timeout. That made a busy moment
  // look like a server fault to the admin, and — worse — it held the one global
  // script lock for the entire payload computation, starving real mutations like
  // Delete User, which then failed with "Lock timeout: another process was
  // holding the lock for too long".
  //
  // Now: try briefly to be the single computer, but never fail and never block
  // a mutation for long. If the lock is busy, just compute anyway.
  var lock = LockService.getScriptLock();
  var locked = false;
  try { locked = lock.tryLock(4000); } catch (e) { locked = false; }

  try {
    // Whoever held the lock may have just finished populating the cache.
    cached = chunkedCacheGet(cache, 'dashboardData');
    if (cached) {
      try { return JSON.parse(cached); } catch(e) {}
    }

    var data = getDashboardData_uncached_();
    try {
      chunkedCachePut(cache, 'dashboardData', JSON.stringify(data), 300); // 5 mins
    } catch(e) {
      log_('Cache skip: data too large (' + e.message + ')');
    }
    return data;
  } finally {
    if (locked) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

function getDashboardData_uncached_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  // 1. Registered Developers (active — compliance is tracked against this list)
  ensureRegisteredDevelopersSheet();
  var regSheet_ = ss.getSheetByName('RegisteredDevelopers');
  var regData_ = regSheet_ ? regSheet_.getDataRange().getValues() : [];
  // v5: removed users are excluded from the compliance roster — they keep their
  // row (so their reports stay searchable for the retention window) but must
  // not inflate "expected" counts or show as perpetually Pending.
  var registeredNames = [];
  for (var ri_ = 1; ri_ < regData_.length; ri_++) {
    if (!regData_[ri_][0]) continue;
    if (normalizeUserStatus_(regData_[ri_][REG_COL_STATUS]) === USER_STATUS.REMOVED) continue;
    registeredNames.push(String(regData_[ri_][0]).trim());
  }

  // 2. Compliance Logs — read all but only keep recent weeks to stay under size limit
  var logSheet = ss.getSheetByName('ComplianceLog');
  var allLogs = [];
  var registeredMap = {};

  // 2a. Compliance grid accumulators (8-week history per registered developer)
  var weekHeaders = getWeekHeaders_(8);
  var weekHeaderSet = {};
  weekHeaders.forEach(function(w) { weekHeaderSet[w] = true; });
  var complianceGrid = {};
  registeredNames.forEach(function(n) { complianceGrid[n] = {}; });
  var recentUploadsAll = [];
  var STATUS_RANK = { 'SUCCESS': 2, 'FAILURE': 1 };

  if (logSheet) {
    // v2: bumped from 3000 → 8000 rows so 90-day compliance windows resolve
    // correctly at 50-dev fleet scale. The Trend chart needs at least 12 weeks
    // of SUCCESS/FAILURE history, which 3000 rows didn't cover.
    var logData = getRecentLogRows_(logSheet, 8000);
    for (var i = 0; i < logData.length; i++) {
      var row = logData[i];
      if (!row[0]) continue;

      var ts = row[0];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
      else ts = String(ts);

      var ws = row[2];
      if (ws && typeof ws.getTime === 'function') {
        ws = Utilities.formatDate(ws, Session.getScriptTimeZone(), 'yyyy-MM-dd');
      } else {
        ws = String(ws);
      }

      var name = String(row[1]).trim();
      var status = String(row[3]).trim().toUpperCase();
      var errMsg = String(row[4] || '');
      // Truncate long error messages to save space
      if (errMsg.length > 120) errMsg = errMsg.substring(0, 120) + '...';

      allLogs.push({
        timestamp: ts,
        name: name,
        weekStart: ws,
        status: status,
        error: errMsg
      });

      // 8-week compliance grid (SUCCESS > FAILURE > null precedence)
      if (weekHeaderSet[ws]) {
        if (!complianceGrid[name]) complianceGrid[name] = {};
        var existingStatus = complianceGrid[name][ws];
        var incomingRank = STATUS_RANK[status] || 0;
        var existingRank = STATUS_RANK[existingStatus] || 0;
        if (incomingRank > existingRank) {
          complianceGrid[name][ws] = status;
        } else if (!existingStatus) {
          complianceGrid[name][ws] = null;
        }
      }

      // Recent uploads log (SUCCESS and FAILURE only)
      if (status === 'SUCCESS' || status === 'FAILURE') {
        recentUploadsAll.push({
          name: name,
          timestamp: ts,
          weekStart: ws,
          status: status,
          version: row[6] ? String(row[6]).trim() : '',
          message: errMsg
        });
      }

      // Track registered developers across ALL logs (not just recent)
      if (status === 'REGISTERED') {
        if (!registeredMap[name] || new Date(ts) < new Date(registeredMap[name])) {
          registeredMap[name] = ts;
        }
      }
    }
  }

  // 2b. Sort recentUploads newest-first, keep top 30
  recentUploadsAll.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
  var recentUploads = recentUploadsAll.slice(0, 30);

  // 3. Distinct weeks (newest first) — keep only most recent 8 weeks for dashboard
  var weeksMap = {};
  allLogs.forEach(function(log) { if (log.weekStart) weeksMap[log.weekStart] = true; });
  var weeks = Object.keys(weeksMap).sort().reverse().slice(0, 8);
  var recentWeeksSet = {};
  weeks.forEach(function(w) { recentWeeksSet[w] = true; });

  // 4. Calculate complianceByWeek based on RegisteredDevelopers (active users)
  var complianceByWeek = {};
  weeks.forEach(function(w) {
    complianceByWeek[w] = { expected: 0, reported: 0, failed: 0, pending: 0, details: [] };
    var devStatus = {};
    registeredNames.forEach(function(n) { devStatus[n] = null; });
    
    var weekLogs = allLogs.filter(function(l) { return l.weekStart === w; });
    weekLogs.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });

    weekLogs.forEach(function(l) {
      if (devStatus[l.name] === undefined) return;
      if (devStatus[l.name] === null) devStatus[l.name] = l;
    });

    Object.keys(devStatus).forEach(function(dev) {
      var l = devStatus[dev];
      complianceByWeek[w].expected++;
      if (!l) {
         complianceByWeek[w].pending++;
         complianceByWeek[w].details.push({ name: dev, status: 'PENDING', ping: '' });
      } else if (['SUCCESS', 'REPORTED', 'COMPLIANT'].indexOf(l.status) !== -1) {
         complianceByWeek[w].reported++;
         complianceByWeek[w].details.push({ name: dev, status: l.status, ping: l.timestamp });
      } else if (['FAILURE', 'ERROR'].indexOf(l.status) !== -1) {
         complianceByWeek[w].failed++;
         complianceByWeek[w].details.push({ name: dev, status: l.status, ping: l.timestamp });
      } else {
         complianceByWeek[w].pending++;
         complianceByWeek[w].details.push({ name: dev, status: l.status, ping: l.timestamp });
      }
    });
  });

  // 5. Registered developers list (from RegisteredDevelopers sheet, with
  // registration date). v5: carries email/system/status. Removed users are
  // split into their own list so the roster table shows only live users while
  // the Removed Users card can still surface them during their retention window.
  var registeredDevelopers = [];
  var removedUsers = [];
  regData_.slice(1).filter(function(r){ return r[0]; }).forEach(function(r) {
    var removedAt = r[REG_COL_REMOVED] ? String(r[REG_COL_REMOVED]).trim() : '';
    var entry = {
      name:         String(r[0]).trim(),
      registeredAt: r[1] ? String(r[1]).trim() : '',
      email:        r[REG_COL_EMAIL]  ? String(r[REG_COL_EMAIL]).trim()  : '',
      system:       r[REG_COL_SYSTEM] ? String(r[REG_COL_SYSTEM]).trim() : '',
      status:       normalizeUserStatus_(r[REG_COL_STATUS]),
      removedAt:    removedAt
    };
    if (entry.status === USER_STATUS.REMOVED) {
      entry.retentionDaysLeft = removedRetentionDaysLeft_(removedAt);
      removedUsers.push(entry);
    } else {
      registeredDevelopers.push(entry);
    }
  });

  // 6. Active users with heartbeat / last-seen / pong data
  var activeUsers = getActiveUsers();

  // 7. Pending trigger queue
  var triggerQueue = adminGetTriggerQueue();

  // 8. Paused developers
  var pausedDevelopers = getPausedDevelopersList();

  return {
    methodologyVersion: 'v2.0',
    schemaVersion: SHEET_SCHEMA_VERSION,
    latestVersion: getLatestVersion(),
    registeredDevelopers: registeredDevelopers,
    removedUsers: removedUsers,
    removedRetentionDays: REMOVED_RETENTION_DAYS,
    utilityDownload: getUtilityDownloadConfig(),
    weeks: weeks,
    complianceByWeek: complianceByWeek,
    activeUsers: activeUsers,
    triggerQueue: triggerQueue,
    currentWeek: getCurrentWeekStart_(),
    pausedDevelopers: pausedDevelopers,
    uploadFrequency: getSetting_('uploadFrequency', 'weekly'),
    uploadSchedule: getUploadSchedule_(),
    complianceGrid: complianceGrid,
    recentUploads: recentUploads,
    weekHeaders: weekHeaders,
    generatedAt: new Date().toISOString()
  };
}

// v2: latest binary version source — replaces the hardcoded LATEST_VERSION
// constant on the client. Reads from Script Properties (admin-editable via
// setLatestVersion, called by the release process) and falls back to a
// sensible default for first-deploy compatibility.
//
// v3: dropped the UrlFetchApp(gist) lookup. It required the
// script.external_request OAuth scope, which is only granted through an
// interactive consent screen in the Apps Script editor — a headless
// `clasp push`/redeploy can never grant it, so every dashboard load was
// silently failing this fetch and serving a stale hardcoded fallback
// instead. Script Properties is a strictly better source of truth here:
// the release process already knows the exact version it just shipped and
// can set it directly, with no external call and no extra scope needed.
function getLatestVersion() {
  var fallback = '2.0.5';
  try {
    var v = PropertiesService.getScriptProperties().getProperty('latest_uploader_version');
    if (v && v.length > 0) return v.trim();
  } catch (e) {}
  return fallback;
}

function setLatestVersion(version) {
  requireAdmin_();
  if (!version) return { success: false, error: 'version required' };
  PropertiesService.getScriptProperties().setProperty('latest_uploader_version', String(version).trim());
  return { success: true, latestVersion: getLatestVersion() };
}

// -------------------- CSV LOG EXPORT --------------------
// Returns the full ComplianceLog as a raw CSV string.
// Only SUCCESS and FAILURE rows are exported (all weeks, not just recent).
function getComplianceLogCSV() {
  requireAdmin_();
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('ComplianceLog');
  if (!sheet) return 'Timestamp,Developer Name,Week Start,Status,Error Message,Version\n';

  var lastRow = sheet.getLastRow();
  if (lastRow <= 1) return 'Timestamp,Developer Name,Week Start,Status,Error Message,Version\n';

  var data = sheet.getRange(1, 1, lastRow, Math.max(sheet.getLastColumn(), 8)).getValues();
  var lines = ['Timestamp,Developer Name,Week Start,Status,Error Message,Version'];

  function csvCell(val) {
    var s = String(val === null || val === undefined ? '' : val);
    // Dates
    if (val && typeof val.toISOString === 'function') s = val.toISOString();
    // v2: CSV-injection guard — prefix cells beginning with =, +, -, @, or
    // tab/cr so Excel/Sheets treats them as literal text, not formulas.
    if (s.length > 0 && /^[=+\-@\t\r]/.test(s)) {
      s = "'" + s;
    }
    // Escape quotes and wrap in quotes if necessary
    if (s.indexOf(',') !== -1 || s.indexOf('"') !== -1 || s.indexOf('\n') !== -1) {
      s = '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  for (var i = 1; i < data.length; i++) {
    var row = data[i];
    if (!row[0]) continue;
    var status = String(row[3] || '').trim().toUpperCase();
    // Export all meaningful events — SUCCESS, FAILURE, GENERATE_START, UPLOAD_START, etc.
    // Skip pure noise (HEARTBEAT / WAITING) to keep the CSV manageable
    if (status === 'HEARTBEAT' || status === 'WAITING') continue;
    lines.push([
      csvCell(row[0]),
      csvCell(row[1]),
      csvCell(row[2]),
      csvCell(row[3]),
      csvCell(row[4]),
      csvCell(row[6]) // Version column
    ].join(','));
  }
  return lines.join('\r\n');
}

// -------------------- GLOBAL QUEUE STATUS --------------------
// Returns a summary of pending + in-progress runs for the dashboard status bar.
// Designed to be lightweight — does NOT do a full getDashboardData rebuild.
function getGlobalQueueStatus() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  // 1. Pending triggers
  var pending = adminGetTriggerQueue();

  // 2. Currently in-progress (last 30 min, terminal not yet received)
  var pendingNames = {};
  pending.forEach(function(p) { pendingNames[p.name.toLowerCase()] = true; });
  var inProgress = getInProgressRuns_(ss, pendingNames);

  // 3. Completed runs this session — scan last 30 min of ComplianceLog for SUCCESS/FAILURE
  var logSheet = ss.getSheetByName('ComplianceLog');
  var recentCompleted = [];
  if (logSheet) {
    var cutoff = new Date(Date.now() - 30 * 60 * 1000);
    var rows = getRecentLogRows_(logSheet, 300);
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row[0]) continue;
      var ts = row[0];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString(); else ts = String(ts);
      if (new Date(ts) < cutoff) continue;
      var status = String(row[3] || '').trim().toUpperCase();
      if (status !== 'SUCCESS' && status !== 'FAILURE') continue;
      var name = String(row[1] || '').trim();
      if (!name) continue;
      recentCompleted.push({
        name: name,
        status: status,
        message: String(row[4] || ''),
        timestamp: ts
      });
    }
    // Deduplicate: keep only the most recent terminal result per developer
    var seenNames = {};
    recentCompleted = recentCompleted.reverse().filter(function(r) {
      if (seenNames[r.name.toLowerCase()]) return false;
      seenNames[r.name.toLowerCase()] = true;
      return true;
    }).reverse();
  }

  return {
    pending: pending,
    inProgress: inProgress.map(function(r) { return { name: r.name }; }),
    recentCompleted: recentCompleted,
    totalQueued: pending.length,
    inProgressCount: inProgress.length,
    completedCount: recentCompleted.length
  };
}

// -------------------- SMART RETRY (SERVER-SIDE) --------------------
// Called from doPost() on every HEARTBEAT/WAITING ping.
// Guards:
//   1. User must have a FAILURE this week with no subsequent SUCCESS.
//   2. No trigger already queued for this user.
//   3. At least 4 hours since last smart retry (PropertiesService cooldown key).
//   4. At most 3 smart retries per user per week (weekly counter in Properties).
function checkAndTriggerSmartRetry_(name) {
  if (!name || name === 'UNKNOWN') return;

  // Guard 1: skip if already queued (fast path via cached queue rows)
  var queueRows = getTriggerQueueRowsCached_();
  var nameLower = name.trim().toLowerCase();
  for (var q = 0; q < queueRows.length; q++) {
    if (queueRows[q].name.toLowerCase() === nameLower) return; // already pending
  }

  // Guard 2: Check cooldown + weekly cap via PropertiesService
  var props = PropertiesService.getScriptProperties();
  var weekKey = getCurrentWeekStart_();
  var cooldownPropKey  = 'smartRetry_cooldown_'  + nameLower;
  var counterPropKey   = 'smartRetry_count_'     + nameLower + '_' + weekKey;

  var lastRetryStr = props.getProperty(cooldownPropKey);
  if (lastRetryStr) {
    var msSince = Date.now() - parseInt(lastRetryStr, 10);
    if (msSince < 4 * 60 * 60 * 1000) return; // < 4 hours — still in cooldown
  }

  var retryCountStr = props.getProperty(counterPropKey);
  var retryCount = retryCountStr ? parseInt(retryCountStr, 10) : 0;
  if (retryCount >= 3) return; // hit weekly cap

  // Guard 3: Confirm there is an actual FAILURE this week with no later SUCCESS.
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var logSheet = ss.getSheetByName('ComplianceLog');
  if (!logSheet) return;

  var logData = getRecentLogRows_(logSheet, 500);
  var latestFailureTs = null;
  var latestSuccessTs = null;

  for (var i = 0; i < logData.length; i++) {
    var row = logData[i];
    if (!row[0]) continue;
    var rName = String(row[1] || '').trim().toLowerCase();
    if (rName !== nameLower) continue;

    var ws = row[2];
    if (ws && typeof ws.getTime === 'function') ws = Utilities.formatDate(ws, Session.getScriptTimeZone(), 'yyyy-MM-dd');
    else ws = String(ws || '');
    if (ws !== weekKey) continue; // only check this week

    var status = String(row[3] || '').trim().toUpperCase();
    var ts = row[0];
    if (ts && typeof ts.getTime === 'function') ts = ts.toISOString(); else ts = String(ts);

    if (status === 'FAILURE') {
      if (!latestFailureTs || new Date(ts) > new Date(latestFailureTs)) latestFailureTs = ts;
    }
    if (status === 'SUCCESS') {
      if (!latestSuccessTs || new Date(ts) > new Date(latestSuccessTs)) latestSuccessTs = ts;
    }
  }

  // Condition: had a FAILURE this week, and no SUCCESS after it
  if (!latestFailureTs) return; // no failure this week
  if (latestSuccessTs && new Date(latestSuccessTs) > new Date(latestFailureTs)) return; // already succeeded

  // All guards passed — queue the smart retry
  var who = 'system:smartRetry';
  var qSheet = ensureTriggerQueue();
  // Double-check under lock that nobody else queued in the meantime
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return;
  try {
    var freshData = qSheet.getDataRange().getValues();
    for (var j = 1; j < freshData.length; j++) {
      if (String(freshData[j][0]).trim().toLowerCase() === nameLower) return; // raced — already queued
    }
    var notBefore = new Date().toISOString();
    qSheet.appendRow([name.trim(), new Date().toISOString(), who, 'FORCE_RUN', notBefore]);
    SpreadsheetApp.flush();

    // Update cooldown + counter
    props.setProperty(cooldownPropKey,  String(Date.now()));
    props.setProperty(counterPropKey,   String(retryCount + 1));

    log_('SmartRetry: queued FORCE_RUN for ' + name +
         ' (attempt ' + (retryCount + 1) + '/3 this week, failure at ' + latestFailureTs + ')');
    invalidateCache_();
  } finally {
    lock.releaseLock();
  }
}

// -------------------- DAILY AUTO-GENERATE (v2) --------------------
// For every developer that pings online, the FIRST time they're seen each
// day, wait 10 minutes (so they're stable / not mid-boot) and then queue a
// FORCE_RUN so reports get generated + uploaded that day automatically.
// Skips users that are paused, already have a pending trigger, or have
// already successfully uploaded today.
//
// CHANGED 2026-07-31 — DAILY -> WEEKLY (Mon 00:00 IST to Sun 23:59 IST).
//
// Requirement: one report per person per reporting week, not one per day. A
// machine that comes online at any point during the week gets its report
// generated 10 minutes later; a machine already counted for that week is left
// alone until the next Monday rolls over.
//
// The "already generated" flag MOVED from CacheService to ScriptProperties, and
// that move is required, not cosmetic. Apps Script caps CacheService expiry at
// 21600s (6 hours) — the old `23 * 3600` was silently clamped to 6h, so the
// supposedly once-a-day guard actually lapsed four times a day and re-queued
// each person repeatedly. (That is why a quiet fleet was still logging hundreds
// of uploads per day.) A week is 168 hours, so cache cannot express it at all;
// ScriptProperties has no TTL and holds the state properly.
//
// Storage shape is ONE property holding {name: weekStart}, not one property per
// person, so it stays a couple of KB for the whole fleet and prunes itself as
// weeks roll over — no unbounded Properties growth.
var AUTOGEN_DELAY_MS = 10 * 60 * 1000;  // 10 minutes after first heartbeat of the week
var AUTOGEN_FIRSTSEEN_TTL_S = 6 * 3600; // cache only holds the short first-seen mark
var WEEKLY_GEN_STATE_KEY = 'weeklyGenQueued';

// {lowercaseName: 'yyyy-MM-dd' weekStart} — the week each person was last queued for.
function getWeeklyGenState_() {
  try {
    return JSON.parse(PropertiesService.getScriptProperties()
      .getProperty(WEEKLY_GEN_STATE_KEY) || '{}');
  } catch (e) { return {}; }
}

// Records that `name` has been handled for `weekStart`, and drops entries from
// any earlier week so this can never grow without bound.
function markWeeklyGenQueued_(name, weekStart) {
  var state = getWeeklyGenState_();
  state[String(name).trim().toLowerCase()] = weekStart;
  Object.keys(state).forEach(function(k) {
    if (state[k] !== weekStart) delete state[k];
  });
  PropertiesService.getScriptProperties()
    .setProperty(WEEKLY_GEN_STATE_KEY, JSON.stringify(state));
}

function getAutoGenerateEnabled_() {
  try {
    // Default = ON. Admin can disable via Script Properties: autogen_daily_enabled=0
    var v = PropertiesService.getScriptProperties().getProperty('autogen_daily_enabled');
    return v !== '0' && v !== 'false';
  } catch (e) { return true; }
}

function setAutoGenerateEnabled(enabled) {
  requireAdmin_();
  PropertiesService.getScriptProperties().setProperty('autogen_daily_enabled', enabled ? '1' : '0');
  return { success: true, enabled: !!enabled };
}

function getAutoGenerateStatus() {
  return {
    enabled: getAutoGenerateEnabled_(),
    delayMinutes: Math.round(AUTOGEN_DELAY_MS / 60000),
    cadence: 'weekly (Mon 00:00 - Sun 23:59 ' + (Session.getScriptTimeZone() || 'Asia/Kolkata') + ')',
    description: 'Once per reporting week, 10 minutes after a developer first comes online that week, ' +
                 'a FORCE_RUN is queued so their weekly report uploads automatically. Someone who ' +
                 'only powers on later in the week still gets captured whenever they appear.'
  };
}

function maybeQueueDailyAutoGenerate_(name) {
  if (!getAutoGenerateEnabled_()) return;
  if (!name || name === 'UNKNOWN') return;

  var cache = CacheService.getScriptCache();
  var weekStart = getCurrentWeekStart_();          // Monday of the current week, script tz
  var lower = name.trim().toLowerCase();
  var firstSeenKey = 'autogen_firstseen_' + weekStart + '_' + lower;

  // Already generated for THIS week? Nothing more to do until Monday rolls over.
  // Read from ScriptProperties, not cache — a week outlives any cache entry.
  var weeklyState = getWeeklyGenState_();
  if (weeklyState[lower] === weekStart) return;

  var now = Date.now();
  var firstSeenStr = cache.get(firstSeenKey);
  if (!firstSeenStr) {
    // First heartbeat observed for this person this week — record and wait out
    // the 10-minute stabilisation window before generating.
    cache.put(firstSeenKey, String(now), AUTOGEN_FIRSTSEEN_TTL_S);
    return;
  }
  var firstSeen = parseInt(firstSeenStr, 10);
  if (!isFinite(firstSeen) || now - firstSeen < AUTOGEN_DELAY_MS) return; // still stabilising

  // Cheap pre-checks before grabbing the script lock
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  if (isDeveloperPaused_(ss, name)) {
    // Paused/removed people are deliberately silent — mark them done for the
    // week so every subsequent heartbeat skips this whole check.
    markWeeklyGenQueued_(name, weekStart);
    return;
  }

  // Skip if a trigger of any type is already pending for this user
  var queueRows = getTriggerQueueRowsCached_();
  for (var q = 0; q < queueRows.length; q++) {
    if (queueRows[q].name.toLowerCase() === lower) {
      markWeeklyGenQueued_(name, weekStart);
      return;
    }
  }

  // NOTE — deliberately NOT scanning ComplianceLog here.
  //
  // The weekly change first shipped with getRecentLogRows_(logSheet, 3000) at
  // this point, to answer "did they already upload this week?". That was a bad
  // regression: ~24,000 cells read on the HEARTBEAT path, for every online
  // agent, several times an hour. At ~22 concurrent agents it drove doGet
  // latency up and contributed to Apps Script's "too many scripts running
  // simultaneously" ceiling.
  //
  // The same question is now answered for free, event-driven: doPost stamps the
  // weekly flag the moment it records a SUCCESS, so the cheap ScriptProperties
  // check at the top of this function already covers it. Worst case, if a flag
  // is somehow missing, one extra report is generated — harmless, and vastly
  // preferable to a 24,000-cell read on the hot path.

  // Queue the trigger under lock (race-safe — same pattern as SmartRetry)
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return;
  try {
    // Re-check inside the lock: both the queue AND the weekly flag, since a
    // concurrent heartbeat for the same person may have just claimed it.
    if (getWeeklyGenState_()[lower] === weekStart) return;
    var qSheet = ensureTriggerQueue();
    var freshData = qSheet.getDataRange().getValues();
    for (var j = 1; j < freshData.length; j++) {
      if (String(freshData[j][0]).trim().toLowerCase() === lower) {
        markWeeklyGenQueued_(name, weekStart);
        return;
      }
    }
    var who = 'system:autoWeekly';
    var notBefore = new Date().toISOString();
    qSheet.appendRow([name.trim(), new Date().toISOString(), who, 'FORCE_RUN', notBefore]);
    SpreadsheetApp.flush();
    markWeeklyGenQueued_(name, weekStart);
    log_('AutoWeekly: queued FORCE_RUN for ' + name + ' (week of ' + weekStart +
         ', first online ' + Math.round((now - firstSeen) / 60000) + ' min ago)');
    invalidateCache_();
  } finally {
    lock.releaseLock();
  }
}

// Admin escape hatch: clears the "already generated this week" flags so the
// next heartbeat from each person re-queues them. Use after fixing a systemic
// problem mid-week when you want everyone to report again without waiting for
// Monday, instead of clicking Generate 77 times.
function adminResetWeeklyGenerationFlags() {
  requireAdmin_();
  var before = Object.keys(getWeeklyGenState_()).length;
  PropertiesService.getScriptProperties().deleteProperty(WEEKLY_GEN_STATE_KEY);
  log_('AutoWeekly: cleared ' + before + ' weekly-generation flag(s) by admin request');
  return {
    success: true,
    cleared: before,
    note: 'Each person re-generates ~10 minutes after their next heartbeat.'
  };
}

function logResetWeeklyGenerationFlags() {
  Logger.log(JSON.stringify(adminResetWeeklyGenerationFlags(), null, 2));
}

// -------------------- WEBHOOK (POST) --------------------

// v3: single write path for live developer activity. Locates (or registers)
// the developer's row in RegisteredDevelopers and updates the activity
// columns (3–9) with ONE setValues call. Returns nothing; errors propagate
// to doPost's catch. Concurrency note: Sheets cell writes are atomic and
// each developer only ever touches their own row, so no ScriptLock is taken
// (a lock here would starve getDashboardData, same rationale as doPost).
function upsertRosterActivity_(name, status, version, nextPollAt, lastUpdateCheck) {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var nameLower = name.trim().toLowerCase();
  var rowIdx = -1;
  for (var r = 1; r < data.length; r++) {
    if (String(data[r][0]).trim().toLowerCase() === nameLower) { rowIdx = r + 1; break; }
  }

  var nowIso = new Date().toISOString();
  if (rowIdx === -1) {
    // First ping — auto-register. v5: self-registered developers land as Active
    // with no email/system on file; the admin fills those in from the Users
    // page (they are only needed to *send* mail, never to track compliance).
    sheet.appendRow([name.trim(), nowIso, nowIso, '', '', '', version || '', nextPollAt || '', lastUpdateCheck || '',
                     '', '', USER_STATUS.ACTIVE, '']);
    log_('Registered new developer: ' + name);
    invalidateCache_(); // roster mutation — full flush
    return;
  }

  // Existing row: merge updates into current values, write cols 3–9 in one call
  var cur = data[rowIdx - 1]; // 0-based row from the same read
  var vals = [
    nowIso,                                                   // 3 LastSeen
    cur[3] ? String(cur[3]) : '',                             // 4 LastHeartbeat
    cur[4] ? String(cur[4]) : '',                             // 5 LastPong
    cur[5] ? String(cur[5]) : '',                             // 6 LastUpload
    version ? String(version) : (cur[6] ? String(cur[6]) : ''), // 7 Version
    nextPollAt ? String(nextPollAt) : (cur[7] ? String(cur[7]) : ''), // 8 NextPollAt
    (lastUpdateCheck && lastUpdateCheck !== 'never') ? String(lastUpdateCheck) : (cur[8] ? String(cur[8]) : '') // 9 LastUpdateCheck
  ];
  if (status === STATUS.HEARTBEAT || status === STATUS.WAITING || status === STATUS.POLLING_ACK ||
      status === STATUS.PAUSED || status === STATUS.WAITING_PAUSED) {
    vals[1] = nowIso; // LastHeartbeat
  }
  if (status === STATUS.PONG)    vals[2] = nowIso; // LastPong
  if (status === STATUS.SUCCESS) vals[3] = nowIso; // LastUpload
  sheet.getRange(rowIdx, 3, 1, 7).setValues([vals]);
}

// -------------------- DRAIN MODE (incident brake) --------------------
//
// Why this exists (added 2026-07-31 after a self-sustaining outage):
//
// The agent keeps a replay queue of pings it failed to deliver, and retries them
// on a timer. Pre-2.0.9 agents replay the ENTIRE queue every cycle and re-queue
// anything that fails again. So a brief server hiccup makes the queue grow, which
// raises the fleet's request rate, which keeps the server saturated — the account
// pins at Google's 30-concurrent-execution ceiling and the admin dashboard can
// never win a slot. It does not recover on its own.
//
// Fixing the agent is the real answer, but that requires a release reaching every
// machine. Drain mode is the lever that works from the server alone, TODAY, on
// agents already in the field:
//
//   Concurrent slots = arrival rate x duration  (Little's Law)
//
// We cannot lower the arrival rate of agents already built. We CAN collapse the
// duration. Acknowledging a keep-alive costs ~30ms instead of ~300ms+, so the
// same flood occupies ~10x fewer slots.
//
// Better still, it is self-terminating: the agent removes a ping from its queue
// as soon as the server returns ok. So drain mode does not just absorb the
// backlog — it makes the backlog disappear. Turn it on during an incident, leave
// it until queues empty, then turn it off.
//
// What is given up while it is on: keep-alive pings are acknowledged without
// updating "last seen", so live presence goes stale and developers may read as
// Offline. Real events (SUCCESS / FAILURE / lifecycle) are NEVER dropped — they
// are not noise statuses and take the normal path. No compliance data is lost.
var DRAIN_MODE_PROP = 'drainMode';

// -------------------- INGEST RATE INSTRUMENTATION --------------------
// Added 2026-08-03. The account keeps hitting Google's 30-concurrent-execution
// ceiling and every diagnosis so far has been inference from reading code. This
// measures the one number that actually decides the question: how many requests
// per minute is the fleet really sending?
//
//   ~26/min  -> baseline (22 agents polling 60s + heartbeat 5min). The fleet is
//               innocent and something else is consuming the quota.
//   hundreds -> a replay-queue flood, confirming the unbounded retry theory.
//
// Deliberately one cache get + one put, because this sits on the hottest path in
// the system and must not become part of the problem it is measuring. Concurrent
// increments can lose a count; that is fine — we need an order of magnitude, not
// an audit. Buckets expire themselves after 15 minutes.
function countIngest_(kind) {
  try {
    var c = CacheService.getScriptCache();
    var k = 'ingest_' + Math.floor(Date.now() / 60000) + '_' + kind;
    var cur = c.get(k);
    c.put(k, String((cur ? parseInt(cur, 10) : 0) + 1), 900);
  } catch (e) { /* never let measurement break ingestion */ }
}

// Run this from the editor after the system has been live a few minutes.
function logIngestRate() {
  requireAdmin_();
  var c = CacheService.getScriptCache();
  var nowMin = Math.floor(Date.now() / 60000);
  var kinds = ['post', 'poll', 'noise', 'real', 'drained', 'throttled'];
  var rows = [];
  var totals = {};
  kinds.forEach(function(k) { totals[k] = 0; });

  for (var back = 14; back >= 0; back--) {
    var min = nowMin - back;
    var row = { minutesAgo: back };
    var any = false;
    kinds.forEach(function(kind) {
      var v = c.get('ingest_' + min + '_' + kind);
      var n = v ? parseInt(v, 10) : 0;
      row[kind] = n;
      totals[kind] += n;
      if (n) any = true;
    });
    if (any || back < 3) rows.push(row);
  }

  var mins = 15;
  var verdict;
  var postPerMin = totals.post / mins;
  if (totals.post === 0) {
    verdict = 'NO DATA YET — either nothing has arrived, or this build was only just deployed. Wait 3 minutes and run again.';
  } else if (postPerMin < 60) {
    verdict = 'BASELINE (' + postPerMin.toFixed(1) + ' POST/min). Expected is ~26/min for 22 agents. ' +
              'The fleet is NOT flooding — the concurrency ceiling is being consumed by something else. ' +
              'Check the Executions page for long-running functions.';
  } else if (postPerMin < 200) {
    verdict = 'ELEVATED (' + postPerMin.toFixed(1) + ' POST/min, ~' + (postPerMin / 26).toFixed(1) + 'x baseline). ' +
              'Consistent with agents replaying backlogged pings. Enable drain mode to let the queues empty.';
  } else {
    verdict = 'FLOOD CONFIRMED (' + postPerMin.toFixed(1) + ' POST/min, ~' + (postPerMin / 26).toFixed(1) + 'x baseline). ' +
              'This is the replay-queue ratchet. Enable drain mode now (logEnableDrainMode) and ship the v2.0.9 agent.';
  }

  return {
    windowMinutes: mins,
    totals: totals,
    perMinute: {
      post:  +(totals.post / mins).toFixed(1),
      poll:  +(totals.poll / mins).toFixed(1),
      noise: +(totals.noise / mins).toFixed(1),
      real:  +(totals.real / mins).toFixed(1)
    },
    drainModeOn: isDrainMode_(),
    byMinute: rows,
    baselineExpected: '~26 POST/min and ~22 poll/min for 22 agents',
    verdict: verdict
  };
}

function logIngestRateReport() { Logger.log(JSON.stringify(logIngestRate(), null, 2)); }

function isDrainMode_() {
  try {
    var c = CacheService.getScriptCache();
    var v = c.get('drainModeFlag');
    if (v !== null) return v === '1';
    var on = PropertiesService.getScriptProperties().getProperty(DRAIN_MODE_PROP) === '1';
    try { c.put('drainModeFlag', on ? '1' : '0', 60); } catch (e) {}
    return on;
  } catch (e) {
    return false; // fail-open: never let this check itself break ingestion
  }
}

function postOk_(extra) {
  var out = { result: 'ok' };
  if (extra) Object.keys(extra).forEach(function(k) { out[k] = extra[k]; });
  return ContentService.createTextOutput(JSON.stringify(out))
    .setMimeType(ContentService.MimeType.JSON);
}

function adminSetDrainMode(on) {
  requireAdmin_();
  var props = PropertiesService.getScriptProperties();
  if (on) props.setProperty(DRAIN_MODE_PROP, '1');
  else props.deleteProperty(DRAIN_MODE_PROP);
  // Clear the 60s cache so the change takes effect immediately, not in a minute.
  try { CacheService.getScriptCache().remove('drainModeFlag'); } catch (e) {}
  log_('DrainMode: ' + (on ? 'ENABLED — keep-alive pings acknowledged without writes' : 'disabled — normal ingestion resumed'));
  return {
    success: true,
    drainMode: !!on,
    note: on
      ? 'Keep-alive pings are now acked instantly. Agent replay queues will drain. Live presence will read stale until you disable it.'
      : 'Normal ingestion resumed. Presence recovers within ~2 minutes.'
  };
}

function logEnableDrainMode()  { Logger.log(JSON.stringify(adminSetDrainMode(true),  null, 2)); }
function logDisableDrainMode() { Logger.log(JSON.stringify(adminSetDrainMode(false), null, 2)); }
function logDrainModeStatus()  { Logger.log(JSON.stringify({ drainMode: isDrainMode_() }, null, 2)); }

function doPost(e) {
  var sigErr = verifyWebhookSignature_(e);
  if (sigErr) {
    // Parse name for the log if we can (best-effort — body may be malformed)
    var rejName = 'unknown';
    try { rejName = JSON.parse(e.postData.contents).name || rejName; } catch (_) {}
    
    // Throttle signature rejection logging per developer to once every 10 minutes
    var cache = CacheService.getScriptCache();
    var cacheKey = 'log_sig_rej_' + rejName.replace(/\s+/g, '_') + '_' + sigErr.substring(0, 10).replace(/[^a-zA-Z0-9]/g, '');
    if (!cache.get(cacheKey)) {
      log_('doPost: signature rejected for "' + rejName + '" — ' + sigErr);
      cache.put(cacheKey, '1', 600); // 10 minutes cooldown
    }
    
    return ContentService
      .createTextOutput(JSON.stringify({ result: 'error', error: 'invalid_signature', reason: sigErr }))
      .setMimeType(ContentService.MimeType.JSON);
  }
  // Note: No ScriptLock here — Sheet.appendRow() is atomic in GAS and safe under concurrency.
  // A ScriptLock would starve getDashboardData and other concurrent GAS executions.
  try {
    var payload = JSON.parse(e.postData.contents);
    var name            = payload.name            || 'UNKNOWN';
    var status          = payload.status          || 'UNKNOWN';
    var message         = payload.message         || '';
    var nextPollAt      = payload.nextPollAt      || '';
    var version         = payload.version         || '';
    var lastUpdateCheck = payload.lastUpdateCheck || '';

    var isNoise = NOISE_STATUSES.indexOf(status) !== -1;

    countIngest_('post');
    countIngest_(isNoise ? 'noise' : 'real');

    // DRAIN MODE — the emergency brake. See isDrainMode_ for the full rationale.
    // Acknowledges keep-alive pings instantly, touching nothing. Because the
    // agent deletes a queued ping once the server returns ok, this actively
    // DRAINS a replay backlog instead of merely surviving it.
    if (isNoise && isDrainMode_()) {
      countIngest_('drained');
      return postOk_({ drained: true });
    }

    // v3: noise pings (heartbeats, pause/idle pings, pongs) no longer append
    // log rows. They update the developer's RegisteredDevelopers row in-place,
    // which keeps the spreadsheet cell count flat. Repetitive keep-alive
    // statuses are throttled to one roster write per developer per 60s —
    // PONG is exempt because it answers an explicit admin Ping test and a
    // dropped PONG would read as "no response" on the dashboard.
    if (name && name !== 'UNKNOWN') {
      var throttleActive = false;
      if (isNoise && status !== STATUS.PONG) {
        var cache = CacheService.getScriptCache();
        var throttleKey = 'hb_throttle_' + name.trim().toLowerCase();
        if (cache.get(throttleKey)) {
          throttleActive = true;
        } else {
          cache.put(throttleKey, 'true', 60);
        }
      }
      // Return NOW for a throttled keep-alive (added 2026-07-31).
      //
      // A repeat heartbeat inside the 60s window carries no new information, and
      // this is the single hottest path in the system. Returning here means such
      // a request never calls SpreadsheetApp.getActiveSpreadsheet() — which was
      // previously executed unconditionally, on every ping, before anyone knew
      // whether the ping mattered.
      //
      // This matters because concurrent slot usage is arrival-rate x duration
      // (Little's Law). Opening the spreadsheet costs a few hundred ms; this
      // path costs a few tens. Cutting duration ~10x cuts concurrent slots ~10x
      // at the same request rate, which is what stops a replay burst from
      // exhausting the account's 30-execution ceiling.
      //
      // Smart Retry is unaffected: it has its own 180s cooldown, so it could
      // never have fired on a heartbeat throttled at 60s anyway.
      if (throttleActive) {
        countIngest_('throttled');
        return postOk_({ throttled: true });
      }

      upsertRosterActivity_(name, status, version, nextPollAt, lastUpdateCheck);
    }

    if (!isNoise) {
      // Opened lazily — only real lifecycle events need the spreadsheet.
      var ss = SpreadsheetApp.getActiveSpreadsheet();
      // Lifecycle + terminal events still append to ComplianceLog — the Queue
      // page (in-progress detection), progress rows, Smart Retry, compliance
      // grid and CSV export all derive from these rows.
      var sheet = ss.getSheetByName('ComplianceLog');
      if (!sheet) {
        sheet = ss.insertSheet('ComplianceLog');
        sheet.appendRow(['Timestamp', 'Developer Name', 'Week Start Date', 'Status', 'Error Message', 'NextPollAt', 'Version', 'LastUpdateCheck']);
        sheet.getRange(1, 1, 1, 8).setFontWeight('bold');
      }
      var weekStart = getCurrentWeekStart_();
      sheet.appendRow([new Date(), name, weekStart, status, message, nextPollAt, version, lastUpdateCheck]);
      // Event-driven weekly guard: the moment a real upload lands, record that
      // this person is done for the week. This replaces what used to be a
      // 3000-row ComplianceLog scan on the heartbeat path, and is both cheaper
      // and more accurate — it is written by the very event it is tracking.
      // Scoped to SUCCESS only, so a FAILURE still leaves them eligible for a
      // retry rather than being marked complete.
      if (status === STATUS.SUCCESS && name && name !== 'UNKNOWN') {
        try { markWeeklyGenQueued_(name, weekStart); } catch (e) {}
      }
      bumpLastModified_();
    } else {
      // Noise events do not update lastModified, avoiding frequent background client-side auto-refreshes.
    }

    // Smart Retry: whenever a developer is seen online (heartbeat/ping), check if they
    // have a failed upload this week and no trigger queued — if so, auto-queue one.
    // This is throttled by a 4-hour cooldown and a max of 3 retries per week per user.
    // We only fire this on HEARTBEAT/WAITING (the most frequent noise events) so it
    // runs in the background without adding latency to important lifecycle events.
    if ((status === 'HEARTBEAT' || status === 'WAITING') && name && name !== 'UNKNOWN') {
      var cache = CacheService.getScriptCache();
      var checkCacheKey = 'heavy_checks_cooldown_' + name.trim().toLowerCase();
      if (!cache.get(checkCacheKey)) {
        cache.put(checkCacheKey, '1', 180); // 3-minute cooldown
        try { checkAndTriggerSmartRetry_(name); } catch (retryErr) {
          log_('SmartRetry error for ' + name + ': ' + retryErr.message);
        }
        // v2: daily auto-generate — first heartbeat each day records firstSeen,
        // subsequent heartbeats after the 10-min stabilisation window queue a
        // FORCE_RUN (deduped per dev per day, paused/already-queued/already-uploaded skipped)
        try { maybeQueueDailyAutoGenerate_(name); } catch (autoErr) {
          log_('AutoDaily error for ' + name + ': ' + autoErr.message);
        }
      }
    }

    return ContentService.createTextOutput(JSON.stringify({ result: 'ok' })).setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ result: 'error', error: err.message })).setMimeType(ContentService.MimeType.JSON);
  }
}

function simulatePing(name, status, message) {
  requireAdmin_();
  var body = JSON.stringify({ name: name, status: status, message: message });
  var ts   = Math.floor(Date.now() / 1000).toString();
  var sig  = computeHmac256_(getWebhookSecrets_()[0], ts + '.' + body);
  var e = {
    postData:  { contents: body },
    parameter: { _ts: ts, _sig: sig }
  };
  doPost(e);
  return { result: 'ok' };
}

// -------------------- PROGRESS STATUS (for live tracker) --------------------

// Read only the last maxRows rows from a sheet (bottom-N slice).
// Much faster than getDataRange() on sheets with thousands of rows.
function getRecentLogRows_(sheet, maxRows) {
  var last = sheet.getLastRow();
  if (last <= 1) return [];
  var start = Math.max(2, last - maxRows + 1);
  return sheet.getRange(start, 1, last - start + 1, sheet.getLastColumn()).getValues();
}

// Returns current pipeline state for a named developer.
// hasTrigger=true means a FORCE_RUN is still pending in the queue (not yet consumed).
// recentLogs is the last 15 entries so the client can derive the current phase.
// lastNextPollAt: most recent nextPollAt value received from the client.
function getDeveloperProgressStatus(name) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var nameLower = name.trim().toLowerCase();

  var hasTrigger = false;
  var tSheet = ss.getSheetByName('TriggerQueue');
  if (tSheet) {
    var tData = tSheet.getDataRange().getValues();
    for (var i = 1; i < tData.length; i++) {
      var rowName = String(tData[i][0]).trim().toLowerCase();
      var rowType = tData[i][3] ? String(tData[i][3]).trim() : 'FORCE_RUN';
      if (rowName === nameLower && rowType === 'FORCE_RUN') {
        hasTrigger = true;
        break;
      }
    }
  }

  var recentLogs = getDeveloperLogs(name, 15);

  // v3: nextPollAt comes from the roster's NextPollAt column (kept fresh by
  // doPost on every ping that carries one) — HeartbeatLog no longer exists.
  var lastNextPollAt = '';
  var regSheet = ss.getSheetByName('RegisteredDevelopers');
  if (regSheet) {
    var regData = regSheet.getDataRange().getValues();
    for (var j = 1; j < regData.length; j++) {
      if (String(regData[j][0]).trim().toLowerCase() === nameLower) {
        var np = regData[j][7];
        if (np && typeof np.getTime === 'function') np = np.toISOString();
        lastNextPollAt = np ? String(np).trim() : '';
        break;
      }
    }
  }

  return { hasTrigger: hasTrigger, recentLogs: recentLogs, lastNextPollAt: lastNextPollAt };
}

// Optimised batch version: opens each sheet ONCE for all names in a single pass.
// Previously called getDeveloperProgressStatus(n) per name, which opened 3 sheets each time.
function getDeveloperProgressStatusBatch(names) {
  if (!names || !names.length) return {};
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  // Build a lookup set of lowercase names for O(1) membership tests.
  var nameLowerMap = {}; // lowerName -> originalName
  names.forEach(function(n) { nameLowerMap[n.trim().toLowerCase()] = n; });

  // 1. Read TriggerQueue ONCE — find FORCE_RUN entries for any of our names.
  var triggerMap = {};
  var tSheet = ss.getSheetByName('TriggerQueue');
  if (tSheet) {
    var tData = tSheet.getDataRange().getValues();
    for (var i = 1; i < tData.length; i++) {
      var rName = String(tData[i][0] || '').trim().toLowerCase();
      if (!nameLowerMap[rName]) continue;
      var rType = tData[i][3] ? String(tData[i][3]).trim() : 'FORCE_RUN';
      if (rType === 'FORCE_RUN') triggerMap[rName] = true;
    }
  }

  // 2. Read the roster ONCE — NextPollAt column (col 8) per developer.
  var nextPollMap = {};
  var regSheet = ss.getSheetByName('RegisteredDevelopers');
  if (regSheet) {
    var regRows = regSheet.getDataRange().getValues();
    for (var j = 1; j < regRows.length; j++) {
      var rName = String(regRows[j][0] || '').trim().toLowerCase();
      if (!nameLowerMap[rName]) continue;
      var np = regRows[j][7];
      if (np && typeof np.getTime === 'function') np = np.toISOString();
      if (np) nextPollMap[rName] = String(np).trim();
    }
  }

  // 3. Read ComplianceLog ONCE — collect logs for all names.
  var recentLogsMap = {};
  names.forEach(function(n) { recentLogsMap[n.trim().toLowerCase()] = []; });

  function collectLogs(sheetName) {
    var logSheet = ss.getSheetByName(sheetName);
    if (!logSheet) return;
    var data = getRecentLogRows_(logSheet, 300);
    for (var k = 0; k < data.length; k++) {
      var row = data[k];
      if (!row[0]) continue;
      var rn = String(row[1] || '').trim().toLowerCase();
      if (!recentLogsMap.hasOwnProperty(rn)) continue;
      var ts = row[0];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString(); else ts = String(ts);
      recentLogsMap[rn].push({
        timestamp: ts,
        status:    String(row[3] || '').trim().toUpperCase(),
        message:   String(row[4] || '')
      });
    }
  }
  collectLogs('ComplianceLog');

  // 4. Sort each developer's logs and build the result object.
  var result = {};
  names.forEach(function(n) {
    var nl = n.trim().toLowerCase();
    var logs = recentLogsMap[nl] || [];
    logs.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
    result[n] = {
      hasTrigger:     !!triggerMap[nl],
      recentLogs:     logs.slice(0, 15),
      lastNextPollAt: nextPollMap[nl] || ''
    };
  });
  return result;
}

// Returns pending triggers + currently-in-progress pipelines for the Queue page.
function getQueuePageData() {
  requireAdmin_();
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  // 1. Pending triggers (with notBefore for countdown display)
  var pending = adminGetTriggerQueue();

  // 2. In-progress runs: recent log entries showing active pipeline stages
  var pendingNames = {};
  pending.forEach(function(p) { pendingNames[p.name.toLowerCase()] = true; });
  var inProgress = getInProgressRuns_(ss, pendingNames);

  return { pending: pending, inProgress: inProgress };
}

// Scans the last 30 minutes of ComplianceLog for developers with an active pipeline
// (have GENERATE_START or UPLOAD_START but no terminal SUCCESS/FAILURE yet).
// excludeNames: object keyed by lowercase names to skip (already pending in TriggerQueue).
function getInProgressRuns_(ss, excludeNames) {
  var logSheet = ss.getSheetByName('ComplianceLog');
  if (!logSheet) return [];

  var rows = getRecentLogRows_(logSheet, 500);
  var cutoff = new Date(Date.now() - 30 * 60 * 1000); // 30 minutes ago
  var devState = {};

  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (!row[0]) continue;
    var ts = row[0];
    if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
    else ts = String(ts);
    if (new Date(ts) < cutoff) continue;

    var name = String(row[1]).trim();
    var status = String(row[3]).trim().toUpperCase();
    var key = name.toLowerCase();
    if (excludeNames[key]) continue;

    if (!devState[key]) devState[key] = { name: name, terminal: false, active: false };
    if (status === 'SUCCESS' || status === 'FAILURE' || status === 'ERROR' || status === 'UPDATED') {
      devState[key].terminal = true;
    }
    if (status === 'GENERATE_START' || status === 'UPLOAD_START' || status === 'GENERATE_DONE' || status === 'UPDATE_START') {
      devState[key].active = true;
    }
  }

  var result = [];
  Object.keys(devState).forEach(function(key) {
    var d = devState[key];
    if (d.active && !d.terminal) {
      result.push(getDeveloperProgressStatus(d.name));
      result[result.length - 1].name = d.name;
    }
  });
  return result;
}

// -------------------- REGISTERED DEVELOPERS MANAGEMENT --------------------
// v3: the ExpectedDevelopers list (and its CRUD endpoints) was removed.
// Onboarding gaps are now surfaced by the dashboard's CSV Roster
// Reconciliation card, which compares an uploaded HR roster against
// RegisteredDevelopers client-side.

function getRegisteredDevelopersList() {
  requireAdmin_();
  ensureRegisteredDevelopersSheet();
  var data = SpreadsheetApp.getActiveSpreadsheet()
    .getSheetByName('RegisteredDevelopers').getDataRange().getValues();
  return data.slice(1).filter(function(r){ return r[0]; }).map(function(r) {
    return {
      name:         String(r[0]).trim(),
      registeredAt: r[1] ? String(r[1]).trim() : '',
      email:        r[REG_COL_EMAIL]  ? String(r[REG_COL_EMAIL]).trim()  : '',
      system:       r[REG_COL_SYSTEM] ? String(r[REG_COL_SYSTEM]).trim() : '',
      status:       normalizeUserStatus_(r[REG_COL_STATUS])
    };
  });
}

// Locates a developer's roster row. Returns { sheet, rowIdx (1-based), row }
// or null. Callers that mutate must already hold the script lock.
function findRosterRow_(name) {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var target = String(name || '').trim().toLowerCase();
  if (!target) return null;
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim().toLowerCase() === target) {
      return { sheet: sheet, rowIdx: i + 1, row: data[i] };
    }
  }
  return null;
}

// v5: DELETE IS NOW A SOFT DELETE.
//
// Requirement: "reports for removed users should remain available for 120 days
// from the date of removal." The v3 behaviour (delete the row, immediately trash
// the Drive JSONs) made that impossible, so removal now stamps
// Status=Removed + RemovedAt and leaves both the row and the report files
// alone. purgeExpiredRemovedUsers() does the destructive part once the
// retention window has elapsed; adminHardDeleteUser() is the manual override.
//
// The developer is also pushed into PausedDevelopers so their agent stops
// uploading on its next poll — otherwise a removed user would keep writing
// fresh reports for the full 120 days.
function removeRegisteredDeveloper(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  name = name.trim();
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var hit = findRosterRow_(name);
    if (!hit) return { success: false, error: name + ' not found in RegisteredDevelopers' };
    if (normalizeUserStatus_(hit.row[REG_COL_STATUS]) === USER_STATUS.REMOVED) {
      return { success: false, error: name + ' is already removed' };
    }

    var nowIso = new Date().toISOString();
    hit.sheet.getRange(hit.rowIdx, REG_COL_STATUS + 1, 1, 2)
      .setValues([[USER_STATUS.REMOVED, nowIso]]);

    // Stop their agent uploading — reuse the existing pause channel, which the
    // client already honours via checkAndClearTrigger's `paused` flag.
    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }
    var pausedSheet = ensurePausedDevelopersSheet_();
    if (!isDeveloperPaused_(SpreadsheetApp.getActiveSpreadsheet(), name)) {
      pausedSheet.appendRow([name, nowIso, who + ' (removed)']);
    }

    invalidateCache_();
    log_('Removed user (soft): ' + name + ' — reports retained until ' +
         addDaysIso_(nowIso, REMOVED_RETENTION_DAYS));
    return {
      success: true,
      status: USER_STATUS.REMOVED,
      removedAt: nowIso,
      retentionDays: REMOVED_RETENTION_DAYS,
      purgeAfter: addDaysIso_(nowIso, REMOVED_RETENTION_DAYS),
      driveFilesDeleted: 0
    };
  } finally {
    lock.releaseLock();
  }
}

// Undo a soft delete inside the retention window.
function adminRestoreUser(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  name = name.trim();
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var hit = findRosterRow_(name);
    if (!hit) return { success: false, error: name + ' not found' };
    if (normalizeUserStatus_(hit.row[REG_COL_STATUS]) !== USER_STATUS.REMOVED) {
      return { success: false, error: name + ' is not removed' };
    }
    hit.sheet.getRange(hit.rowIdx, REG_COL_STATUS + 1, 1, 2)
      .setValues([[USER_STATUS.ACTIVE, '']]);
    invalidateCache_();
    log_('Restored user: ' + name);
  } finally {
    lock.releaseLock();
  }
  // Resume outside the lock — adminResumeDeveloper takes the lock itself.
  try { adminResumeDeveloper(name); } catch (e) { log_('Restore: resume failed for ' + name + ': ' + e); }
  return { success: true, status: USER_STATUS.ACTIVE };
}

// Immediate, irreversible purge: drops the roster row, the paused row, and
// trashes the Drive reports. This is the old v3 removeRegisteredDeveloper
// behaviour, now only reachable when an admin explicitly asks for it.
function adminHardDeleteUser(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  name = name.trim();
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var hit = findRosterRow_(name);
    if (!hit) return { success: false, error: name + ' not found in RegisteredDevelopers' };
    hit.sheet.deleteRow(hit.rowIdx);

    var pausedSheet = ss.getSheetByName('PausedDevelopers');
    if (pausedSheet) {
      var pData = pausedSheet.getDataRange().getValues();
      for (var pIdx = 1; pIdx < pData.length; pIdx++) {
        if (String(pData[pIdx][0]).trim().toLowerCase() === name.toLowerCase()) {
          pausedSheet.deleteRow(pIdx + 1);
          break;
        }
      }
    }
    invalidateCache_();
    log_('Hard-deleted user: ' + name);
  } finally {
    lock.releaseLock();
  }
  // Outside the lock — Drive iteration is slow and must not starve other execs.
  var deleted = deleteUploaderDriveFiles_(name);
  return { success: true, driveFilesDeleted: deleted };
}

// Daily sweep: hard-deletes removed users whose 120-day retention window has
// expired. Admin-gated because it is destructive and this web app is deployed
// with ANYONE_ANONYMOUS access — the scheduled trigger goes through
// purgeExpiredRemovedUsers_internal_ instead, which skips the gate.
function purgeExpiredRemovedUsers() {
  requireAdmin_();
  return purgeExpiredRemovedUsers_internal_();
}

function purgeExpiredRemovedUsers_internal_() {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var expired = [];
  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    if (normalizeUserStatus_(data[i][REG_COL_STATUS]) !== USER_STATUS.REMOVED) continue;
    var removedAt = data[i][REG_COL_REMOVED];
    if (removedAt && typeof removedAt.getTime === 'function') removedAt = removedAt.toISOString();
    removedAt = String(removedAt || '').trim();
    // A Removed row with no RemovedAt stamp has no measurable window — leave it
    // for an admin rather than guessing and destroying reports early.
    if (!removedAt) continue;
    var left = removedRetentionDaysLeft_(removedAt);
    if (left !== null && left <= 0) expired.push(name);
  }
  if (expired.length === 0) return { success: true, purged: 0 };

  var purged = [];
  expired.forEach(function(n) {
    try {
      var r = adminHardDeleteUser_internal_(n);
      if (r && r.success) purged.push(n);
    } catch (e) {
      log_('Retention purge failed for ' + n + ': ' + e.toString());
    }
  });
  if (purged.length > 0) {
    log_('Retention purge: removed ' + purged.length + ' user(s) past ' +
         REMOVED_RETENTION_DAYS + '-day window — ' + purged.join(', '));
  }
  return { success: true, purged: purged.length, names: purged };
}

// Same as adminHardDeleteUser but without the admin gate, so the scheduled
// retention sweep can run with no active user session.
function adminHardDeleteUser_internal_(name) {
  var saved = requireAdmin_;
  requireAdmin_ = function() {};
  try {
    return adminHardDeleteUser(name);
  } finally {
    requireAdmin_ = saved;
  }
}

// Whole-number days remaining in the retention window, or null if unparseable.
// Negative values are clamped to 0 (already due for purge).
function removedRetentionDaysLeft_(removedAtIso) {
  if (!removedAtIso) return null;
  var t = new Date(removedAtIso).getTime();
  if (!isFinite(t)) return null;
  var elapsedDays = (Date.now() - t) / 86400000;
  return Math.max(0, Math.ceil(REMOVED_RETENTION_DAYS - elapsedDays));
}

function addDaysIso_(iso, days) {
  var t = new Date(iso).getTime();
  if (!isFinite(t)) return '';
  return new Date(t + days * 86400000).toISOString();
}

// v5: add-user now carries Email + System and can send the onboarding mail in
// the same call. The old single-argument form still works — the manual
// "Register" box and CSV reconciliation both call addRegisteredDeveloper(name).
function addRegisteredDeveloper(name, email, system) {
  return adminAddUser({ name: name, email: email, system: system, sendEmail: false });
}

// opts: { name, email, system, sendEmail, emailSubject, emailBody }
function adminAddUser(opts) {
  requireAdmin_();
  opts = opts || {};
  var name = String(opts.name || '').trim();
  if (!name) return { success: false, error: 'Name is required' };

  var email = String(opts.email || '').trim();
  if (email && !isValidEmail_(email)) {
    return { success: false, error: 'Not a valid email address: ' + email };
  }
  if (opts.sendEmail && !email) {
    return { success: false, error: 'An email address is required to send the setup email' };
  }
  var system = String(opts.system || '').trim();

  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  var created = false;
  try {
    var sheet = ensureRegisteredDevelopersSheet();
    var existing = findRosterRow_(name);
    if (existing) {
      var exStatus = normalizeUserStatus_(existing.row[REG_COL_STATUS]);
      if (exStatus === USER_STATUS.REMOVED) {
        return {
          success: false,
          error: name + ' was removed and is still inside the ' + REMOVED_RETENTION_DAYS +
                 '-day retention window. Restore them instead of re-adding.',
          canRestore: true
        };
      }
      return { success: false, error: name + ' is already registered' };
    }
    var nowIso = new Date().toISOString();
    sheet.appendRow([name, nowIso, '', '', '', '', '', '', '', email, system, USER_STATUS.ACTIVE, '']);
    created = true;
    invalidateCache_();
    log_('Admin added user: ' + name + (email ? ' <' + email + '>' : '') + (system ? ' [' + system + ']' : ''));
  } finally {
    lock.releaseLock();
  }

  // Send outside the lock — Gmail calls are slow and must not hold the roster.
  var emailResult = { sent: false };
  if (created && opts.sendEmail) {
    emailResult = sendSetupEmail_(
      { name: name, email: email, system: system },
      opts.emailSubject,
      opts.emailBody
    );
  }
  return {
    success: true,
    created: created,
    emailSent: !!emailResult.sent,
    emailError: emailResult.error || null
  };
}

// Edit an existing user's email / system without touching activity columns.
function adminUpdateUser(name, fields) {
  requireAdmin_();
  fields = fields || {};
  if (!name || !String(name).trim()) return { success: false, error: 'Name is required' };
  var email = fields.email === undefined ? null : String(fields.email || '').trim();
  if (email && !isValidEmail_(email)) {
    return { success: false, error: 'Not a valid email address: ' + email };
  }
  var system = fields.system === undefined ? null : String(fields.system || '').trim();

  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var hit = findRosterRow_(name);
    if (!hit) return { success: false, error: name + ' not found' };
    var vals = [
      email  === null ? (hit.row[REG_COL_EMAIL]  || '') : email,
      system === null ? (hit.row[REG_COL_SYSTEM] || '') : system
    ];
    hit.sheet.getRange(hit.rowIdx, REG_COL_EMAIL + 1, 1, 2).setValues([vals]);
    invalidateCache_();
    log_('Updated user ' + name + ': email=' + vals[0] + ' system=' + vals[1]);
    return { success: true, email: vals[0], system: vals[1] };
  } finally {
    lock.releaseLock();
  }
}

function isValidEmail_(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || '').trim());
}

function log_(msg) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('AppLog');
    if (!sheet) { sheet = ss.insertSheet('AppLog'); sheet.appendRow(['Timestamp', 'Message']); }
    sheet.appendRow([new Date(), msg]);
  } catch (e) {
    // Silence logging errors
  }
}

// v3: HeartbeatLog no longer exists (noise pings update the roster
// in-place). Function name retained because the daily time-based trigger
// is installed against 'pruneHeartbeatLog' and survives redeploys.
function pruneHeartbeatLog() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) return;
  try {
    // 1. AppLog: max 1000 rows
    fastPruneLogSheet_(
      'AppLog',
      1000,
      ['Timestamp', 'Message']
    );

    // 2. ComplianceLog: max 5000 rows
    fastPruneLogSheet_(
      'ComplianceLog',
      5000,
      ['Timestamp', 'Developer Name', 'Week Start Date', 'Status', 'Error Message', 'NextPollAt', 'Version', 'LastUpdateCheck']
    );
  } catch(e) {
    log_('Prune error: ' + e.toString());
  } finally {
    lock.releaseLock();
  }

  // 3. v5: retention sweep for soft-deleted users. Deliberately outside the
  // lock above — it takes the script lock itself (via adminHardDeleteUser) and
  // iterates Drive, so nesting would self-deadlock on the 30s wait.
  try {
    purgeExpiredRemovedUsers_internal_(); // no session here — skip the admin gate
  } catch (e) {
    log_('Retention purge error: ' + e.toString());
  }
}

function fastPruneLogSheet_(sheetName, maxRows, headers) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) return;
  
  var lastRow = sheet.getLastRow();
  if (lastRow <= maxRows + 100) return; // not enough rows to prune yet
  
  var keepRows = getRecentLogRows_(sheet, maxRows);
  
  // Clear the entire sheet (values and formatting)
  sheet.clear();
  
  // Write headers
  sheet.appendRow(headers);
  sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  
  // Write kept rows
  if (keepRows.length > 0) {
    var numCols = Math.min(headers.length, keepRows[0].length);
    var cleanKeepRows = keepRows.map(function(row) {
      return row.slice(0, numCols);
    });
    sheet.getRange(2, 1, cleanKeepRows.length, numCols).setValues(cleanKeepRows);
  }
  
  // Shrink the sheet to fit the data plus a small buffer of 50 empty rows
  var currentMaxRows = sheet.getMaxRows();
  var desiredRows = sheet.getLastRow() + 50;
  if (currentMaxRows > desiredRows) {
    sheet.deleteRows(desiredRows + 1, currentMaxRows - desiredRows);
  }
  
  log_('Fast-pruned ' + (lastRow - keepRows.length - 1) + ' rows from ' + sheetName);
}

function adminForcePrune() {
  requireAdmin_();
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) return { success: false, error: 'Could not get lock to prune' };
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheets = ss.getSheets();
    for (var i = 0; i < sheets.length; i++) {
      var s = sheets[i];
      var name = s.getName();
      // Delete excessive empty columns (anything beyond column 15)
      var maxCols = s.getMaxColumns();
      if (maxCols > 15) {
        s.deleteColumns(16, maxCols - 15);
      }
      
      // Prune rows if it's a log sheet
      if (name === 'AppLog') {
        var lr = s.getLastRow();
        if (lr > 1000) s.deleteRows(2, lr - 1000);
      } else if (name === 'ComplianceLog') {
        var lr = s.getLastRow();
        if (lr > 3000) s.deleteRows(2, lr - 3000);
      }
      
      // Delete excessive blank rows below data in ALL sheets
      var lr = s.getLastRow();
      var maxRows = s.getMaxRows();
      if (maxRows > lr && (maxRows - Math.max(lr, 1)) > 100) {
        // Keep a buffer of 100 empty rows, delete the rest
        s.deleteRows(Math.max(lr, 1) + 100, maxRows - Math.max(lr, 1) - 100);
      }
    }
    return { success: true };
  } catch (e) {
    return { success: false, error: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function installPruneTrigger() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i=0; i<triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'pruneHeartbeatLog') return;
  }
  ScriptApp.newTrigger('pruneHeartbeatLog').timeBased().everyDays(1).create();
}

// -------------------- AUTO-STALL ALERT (v2) --------------------
// Scheduled trigger that scans registered developers for stalled services
// (no heartbeat for ≥ stallHoursThreshold) and emails the admin once per
// stall cycle. Cycle = the contiguous staleness window; alerts are deduped
// per developer until they ping again, then a new cycle can fire.

function getStallThresholdHours_() {
  try {
    var v = parseInt(PropertiesService.getScriptProperties().getProperty('stall_threshold_hours') || '24', 10);
    if (isFinite(v) && v >= 1 && v <= 168) return v;
  } catch (e) {}
  return 24;
}

function setStallThresholdHours(hours) {
  requireAdmin_();
  var h = parseInt(hours, 10);
  if (!isFinite(h) || h < 1 || h > 168) return { success: false, error: 'hours must be between 1 and 168' };
  PropertiesService.getScriptProperties().setProperty('stall_threshold_hours', String(h));
  return { success: true, stallThresholdHours: h };
}

function runStallScan() {
  // Designed to be called both manually and from a time-driven trigger.
  // Public (no requireAdmin_) so the scheduler can run it.
  // v3: piggyback the hourly Drive sweep for paused developers' files.
  cleanupPausedDevelopersFiles();
  var threshold = getStallThresholdHours_();
  var thresholdMs = threshold * 3600 * 1000;
  var now = Date.now();
  var users = [];
  try { users = getActiveUsers_internal_(); } catch (e) {
    // Internal call must skip the admin gate.
    users = [];
  }
  var stalled = [];
  users.forEach(function(u) {
    // v5: a removed user's agent is *supposed* to be silent — never alert on it.
    if (u.status === USER_STATUS.REMOVED) return;
    if (!u.lastHeartbeat && !u.lastPong) return; // never pinged — handled by onboarding strip, not stall alert
    var keepAliveMs = 0;
    if (u.lastHeartbeat) keepAliveMs = Math.max(keepAliveMs, new Date(u.lastHeartbeat).getTime());
    if (u.lastPong)      keepAliveMs = Math.max(keepAliveMs, new Date(u.lastPong).getTime());
    if (!keepAliveMs) return;
    var age = now - keepAliveMs;
    if (age >= thresholdMs) stalled.push({ name: u.name, ageHours: Math.round(age / 3600000), lastSeen: new Date(keepAliveMs).toISOString() });
  });

  // Per-developer dedup — only alert once per stall cycle
  var props = PropertiesService.getScriptProperties();
  var alerted = {};
  try { alerted = JSON.parse(props.getProperty('stall_alerted') || '{}'); } catch (e) {}

  // Clear dedup entries for devs that are no longer stalled (so next stall fires)
  var stillStalledNames = {};
  stalled.forEach(function(s) { stillStalledNames[s.name] = true; });
  var newAlerted = {};
  Object.keys(alerted).forEach(function(n) { if (stillStalledNames[n]) newAlerted[n] = alerted[n]; });
  alerted = newAlerted;

  var newlyStalled = stalled.filter(function(s) { return !alerted[s.name]; });

  // Compose + send (one email, all newly-stalled devs)
  if (newlyStalled.length > 0) {
    var allowlist = getAdminAllowlist_();
    if (allowlist.length === 0) {
      log_('AutoStall: ' + newlyStalled.length + ' newly-stalled dev(s), but admin_emails is empty — skipping email');
    } else {
      var subject = '[Claude Usage] ' + newlyStalled.length + ' developer(s) stalled (>' + threshold + 'h)';
      var lines = ['The following developers have not heartbeated in the last ' + threshold + ' hour(s):', ''];
      newlyStalled.forEach(function(s) { lines.push('  • ' + s.name + ' — last seen ' + s.ageHours + 'h ago (' + s.lastSeen + ')'); });
      lines.push('');
      lines.push('Open the Compliance Dashboard → Queue tab to force-run, or check the developer\'s machine.');
      try {
        GmailApp.sendEmail(allowlist.join(','), subject, lines.join('\n'));
        newlyStalled.forEach(function(s) { alerted[s.name] = new Date().toISOString(); });
        log_('AutoStall: alerted on ' + newlyStalled.length + ' dev(s)');
      } catch (e) {
        log_('AutoStall: email send failed: ' + e.toString());
      }
    }
  }
  props.setProperty('stall_alerted', JSON.stringify(alerted));
  return {
    success: true,
    stalledCount: stalled.length,
    newlyAlerted: newlyStalled.length,
    stalled: stalled,
    thresholdHours: threshold
  };
}

// Internal getActiveUsers — same logic without the admin gate, so the
// scheduled stall scan can run without an active user session.
function getActiveUsers_internal_() {
  var oldRequireAdmin = requireAdmin_;
  // Temporarily replace with a no-op (safe — we restore in finally)
  requireAdmin_ = function() {};
  try {
    return getActiveUsers();
  } finally {
    requireAdmin_ = oldRequireAdmin;
  }
}

function installStallTrigger() {
  requireAdmin_();
  var existing = ScriptApp.getProjectTriggers();
  for (var i = 0; i < existing.length; i++) {
    if (existing[i].getHandlerFunction() === 'runStallScan') return { success: true, message: 'Already installed' };
  }
  ScriptApp.newTrigger('runStallScan').timeBased().everyHours(1).create();
  return { success: true, message: 'Stall scan trigger installed (hourly)' };
}

function uninstallStallTrigger() {
  requireAdmin_();
  var existing = ScriptApp.getProjectTriggers();
  var removed = 0;
  for (var i = 0; i < existing.length; i++) {
    if (existing[i].getHandlerFunction() === 'runStallScan') {
      ScriptApp.deleteTrigger(existing[i]);
      removed++;
    }
  }
  return { success: true, removed: removed };
}

function isStallTriggerInstalled() {
  var existing = ScriptApp.getProjectTriggers();
  for (var i = 0; i < existing.length; i++) {
    if (existing[i].getHandlerFunction() === 'runStallScan') return true;
  }
  return false;
}

// v2: signature-rejection log (recent N entries) — surfaced on Health page.
// Reads AppLog rows starting with the prefix we use in doPost.
function getRecentSignatureRejections(limit) {
  requireAdmin_();
  limit = Math.min(limit || 50, 200);
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('AppLog');
  if (!sheet) return [];
  var rows = getRecentLogRows_(sheet, 1000);
  var out = [];
  for (var i = rows.length - 1; i >= 0 && out.length < limit; i--) {
    var msg = String(rows[i][1] || '');
    if (msg.indexOf('doPost: signature rejected') === 0) {
      var ts = rows[i][0];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
      else ts = String(ts);
      out.push({ timestamp: ts, message: msg });
    }
  }
  return out;
}

// v2: bulk cancel pending triggers by name. Used by the new bulk-select UI.
function adminCancelTriggerBatch(names) {
  requireAdmin_();
  if (!Array.isArray(names) || names.length === 0) return { success: false, error: 'No names provided' };
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('TriggerQueue');
  if (!sheet) return { success: true, cancelled: 0 };
  var lr = sheet.getLastRow();
  if (lr <= 1) return { success: true, cancelled: 0 };
  var nameSet = {};
  names.forEach(function(n) { nameSet[String(n).trim().toLowerCase()] = true; });
  var data = sheet.getDataRange().getValues();
  var removed = 0;
  for (var i = data.length - 1; i >= 1; i--) {
    var n = String(data[i][0] || '').trim().toLowerCase();
    if (nameSet[n]) {
      sheet.deleteRow(i + 1);
      removed++;
    }
  }
  invalidateCache_();
  return { success: true, cancelled: removed };
}

// -------------------- COMPLIANCE REMINDERS --------------------

function sendComplianceReminders(force) {
  requireAdmin_();
  var adminEmail = Session.getActiveUser().getEmail();
  if (!adminEmail) return { success: false, error: 'Could not determine admin email. Ensure the web app runs as "User accessing the web app".' };

  var data = getDashboardData_uncached_();
  var currentWeek = data.currentWeek || '';
  var weekData = (data.complianceByWeek && data.complianceByWeek[currentWeek]) ? data.complianceByWeek[currentWeek] : { details: [] };
  var details = weekData.details || [];

  var nonCompliant = details.filter(function(d) {
    return ['SUCCESS', 'REPORTED', 'COMPLIANT'].indexOf(d.status) === -1;
  });

  if (nonCompliant.length === 0) {
    return { success: true, message: 'All developers compliant for ' + currentWeek + '. No reminders needed.' };
  }

  // v2: throttle — at most one reminder per admin per week per current-week,
  // unless explicitly forced. Prevents accidental spam from repeated clicks.
  var throttleKey = 'reminderSent_' + currentWeek + '_' + adminEmail.toLowerCase();
  if (!force) {
    var props = PropertiesService.getScriptProperties();
    var lastSent = props.getProperty(throttleKey);
    if (lastSent) {
      var ageMins = Math.round((Date.now() - parseInt(lastSent, 10)) / 60000);
      return {
        success: false,
        throttled: true,
        sentAt: lastSent,
        message: 'A reminder for week ' + currentWeek + ' was already sent to ' + adminEmail + ' (' + ageMins + ' min ago). Use force=true to override.'
      };
    }
  }

  // Separate failures from pending
  var failed  = nonCompliant.filter(function(d) { return d.status === 'FAILURE' || d.status === 'ERROR'; });
  var pending = nonCompliant.filter(function(d) { return failed.indexOf(d) === -1; });

  var subject = '[Claude Usage] Non-compliant developers — ' + currentWeek;
  var lines = ['The following developers have not submitted Claude usage data for week ' + currentWeek + ':\n'];
  if (failed.length > 0) {
    lines.push('UPLOAD FAILED (' + failed.length + '):');
    failed.forEach(function(d) { lines.push('  • ' + d.name + ' — ' + (d.status || 'FAILURE')); });
    lines.push('');
  }
  if (pending.length > 0) {
    lines.push('PENDING / NOT YET UPLOADED (' + pending.length + '):');
    pending.forEach(function(d) { lines.push('  • ' + d.name); });
    lines.push('');
  }
  lines.push('You can trigger a force-run for any developer from the Compliance Dashboard.');
  lines.push('\nThis message was generated by the Claude Usage Uploader Dashboard.');

  GmailApp.sendEmail(adminEmail, subject, lines.join('\n'));
  // v2: record send timestamp so the per-week throttle works
  try {
    PropertiesService.getScriptProperties().setProperty(throttleKey, String(Date.now()));
  } catch (e) { /* throttle is best-effort */ }
  return { success: true, message: 'Reminder sent to ' + adminEmail + ' for ' + nonCompliant.length + ' non-compliant developer(s).' };
}

// -------------------- DRIVE FILE CLEANUP (v3) --------------------
// Uploaders write <Name_with_underscores>_claude_daily.json and
// _claude_session.json into this shared Drive folder (same ID as the
// uploader's DRIVE_FOLDER_ID). Pausing or deleting a developer trashes
// their files; an hourly sweep inside runStallScan() catches anything a
// paused uploader managed to re-upload before it saw paused=true.
// NOTE: the script's executing account needs Content Manager (or higher)
// on the shared drive — failures are logged, never thrown.
var SHARED_DRIVE_FOLDER_ID = '0AMXBcPT9R10cUk9PVA';

function uploaderFileNamesFor_(name) {
  var prefix = String(name || '').trim().replace(/\s+/g, '_');
  return [prefix + '_claude_daily.json', prefix + '_claude_session.json'];
}

function deleteUploaderDriveFiles_(name) {
  if (!name) return 0;
  var deletedCount = 0;
  try {
    var wanted = {};
    uploaderFileNamesFor_(name).forEach(function(f) { wanted[f] = true; });
    var folder = DriveApp.getFolderById(SHARED_DRIVE_FOLDER_ID);
    var files = folder.getFiles();
    while (files.hasNext()) {
      var file = files.next();
      if (file.isTrashed()) continue;
      if (wanted[file.getName()]) {
        file.setTrashed(true);
        deletedCount++;
      }
    }
    log_('DriveApp: deleted ' + deletedCount + ' file(s) for ' + name);
  } catch (e) {
    log_('DriveApp: error deleting files for ' + name + ': ' + e.toString());
  }
  return deletedCount;
}

// Hourly sweep (called from runStallScan): trash report files belonging to
// any currently-paused developer. Single folder iteration for all names.
function cleanupPausedDevelopersFiles() {
  try {
    var paused = getPausedDevelopersList();
    if (paused.length === 0) return;

    var wanted = {};
    paused.forEach(function(p) {
      uploaderFileNamesFor_(p.name).forEach(function(f) { wanted[f] = true; });
    });

    var folder = DriveApp.getFolderById(SHARED_DRIVE_FOLDER_ID);
    var files = folder.getFiles();
    var deletedCount = 0;
    while (files.hasNext()) {
      var file = files.next();
      if (file.isTrashed()) continue;
      if (wanted[file.getName()]) {
        file.setTrashed(true);
        deletedCount++;
      }
    }
    if (deletedCount > 0) {
      log_('DriveApp: auto-cleanup trashed ' + deletedCount + ' file(s) for paused developers');
    }
  } catch (e) {
    log_('DriveApp: auto-cleanup failed: ' + e.toString());
  }
}

// ================================================================
// v5.2 — WEEKLY REPORT ARCHIVE
// ================================================================
// Requirement: "Reports should be uploaded to folders using the format
// Month-Date Range-Year (e.g. July 20-26 2026)" and "reports for removed users
// should remain available for 120 days".
//
// The uploader overwrites ONE flat file per developer per report type, in place,
// via a PATCH. That means there is no history at all — only ever the latest
// state. Changing that in the client would need a new binary on every machine.
//
// This does it server-side instead: once a week, COPY the flat files into a
// dated folder. The agents are untouched, the flat files keep working exactly as
// they do now, and the dated folders accumulate the immutable weekly history
// that date-range search and retention actually need.
//
// The snapshot re-runs daily against the last completed week for a grace period,
// because a machine that boots on Wednesday still uploads that week's report —
// a single Monday-morning pass would silently miss every late reporter.
var WEEKLY_ARCHIVE_PARENT_ID = '1ss0gkNQPjFRoqRLp2zmGV7SEUp5tbzVu';

// How long after a week closes we keep refreshing its folder with late arrivals.
// After this the folder is left alone and treated as final.
var ARCHIVE_GRACE_DAYS = 10;

// Stop before Apps Script's 6-minute ceiling and let the next daily run resume.
var ARCHIVE_TIME_BUDGET_MS = 4 * 60 * 1000;

// Every folder the fleet might currently be uploading into.
//
// A version-mixed fleet writes to TWO places at once: v2.0.7+ agents use the
// folder configured on the dashboard, while older agents keep using the one
// compiled into their binary. Both must be archived or half the fleet vanishes
// from the weekly history. Returns the configured folder first (when set), then
// the compiled default, de-duplicated.
function archiveSourceFolderIds_() {
  var ids = [];
  // Read the sheet directly, not the cache: the archive runs from a time-driven
  // trigger where a stale 10-minute cache entry could point at the wrong folder.
  var configured = '';
  try { configured = String(getSetting_(UPLOAD_FOLDER_SETTING_KEY, '') || '').trim(); } catch (e) {}
  if (configured) ids.push(configured);
  if (ids.indexOf(SHARED_DRIVE_FOLDER_ID) === -1) ids.push(SHARED_DRIVE_FOLDER_ID);
  return ids;
}

// Verify the script can actually write to the archive parent BEFORE anything
// depends on it. Drive failures here are silent and easy to miss otherwise.
function checkWeeklyArchiveAccess() {
  requireAdmin_();
  var out = { parentFolderId: WEEKLY_ARCHIVE_PARENT_ID };

  // Report every folder the snapshot will read from, and whether it can be read.
  // A source the script cannot open is the failure mode that silently drops a
  // whole cohort of agents from the archive, so surface it here rather than
  // leaving it to be discovered in a log weeks later.
  out.sourceFolders = archiveSourceFolderIds_().map(function(sid) {
    var entry = { folderId: sid, isCompiledDefault: sid === SHARED_DRIVE_FOLDER_ID };
    try {
      var sf = DriveApp.getFolderById(sid);
      entry.folderName = sf.getName();
      entry.canRead = true;
      var c = 0;
      var it = sf.getFiles();
      while (it.hasNext()) { if (/_claude_(daily|session)\.json$/i.test(it.next().getName())) c++; }
      entry.reportFilesPresent = c;
    } catch (e) {
      entry.canRead = false;
      entry.error = e.toString();
      entry.fix = 'Share this folder with the Apps Script owner account (Editor), ' +
                  'or agents uploading here will be missing from every weekly folder.';
    }
    return entry;
  });
  try {
    var parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
    out.parentFolderName = parent.getName();
    out.canRead = true;
  } catch (e) {
    return {
      parentFolderId: WEEKLY_ARCHIVE_PARENT_ID,
      canRead: false,
      canWrite: false,
      error: e.toString(),
      fix: 'Share the archive folder with the account that OWNS this Apps Script ' +
           'project (Deploy > Manage deployments shows "Execute as"), with Editor access.'
    };
  }
  // Write test: create then immediately trash a probe folder.
  try {
    var probe = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID)
      .createFolder('__write_probe_' + Utilities.formatDate(new Date(), 'UTC', 'yyyyMMdd_HHmmss'));
    probe.setTrashed(true);
    out.canWrite = true;
    var badSources = out.sourceFolders.filter(function(s) { return !s.canRead; });
    out.verdict = badSources.length === 0
      ? 'READY. The script can create dated folders in "' + out.parentFolderName + '", and can ' +
        'read all ' + out.sourceFolders.length + ' upload folder(s) the fleet writes to.'
      : 'PARTIAL. Dated folders can be created, but ' + badSources.length + ' of ' +
        out.sourceFolders.length + ' upload folder(s) cannot be read — agents uploading there ' +
        'will be MISSING from every weekly folder. Fix: ' + badSources[0].fix;
  } catch (e) {
    out.canWrite = false;
    out.error = e.toString();
    out.verdict = 'READ-ONLY. The script can see the folder but not write to it — snapshots would fail.';
    out.fix = 'Give the Apps Script owner account Editor (not Viewer) on this folder.';
  }
  return out;
}

// Copy the current flat report files into the dated folder for one week.
// Idempotent: a file already present and not older than the source is skipped.
function snapshotWeeklyReports(weekStartIso, weekEndIso) {
  var win = (weekStartIso && weekEndIso)
    ? { weekStart: weekStartIso, weekEnd: weekEndIso, label: formatWeekLabel_(weekStartIso, weekEndIso) }
    : lastCompletedWeekWindow_();

  var started = Date.now();
  var report = {
    period: win, folderName: win.label,
    copied: [], refreshed: [], skipped: [], movedToCurrentWeek: [], failed: [],
    timedOut: false
  };

  // Fixed 2026-07-30: is `win` itself the week in progress, or an already-closed
  // one? Only a CLOSED week gets the "stop touching this person once they show
  // up in the current week" treatment below — snapshotting the current week
  // (which the daily archive job never does on its own, but this function's
  // signature allows arbitrary dates) must never skip against itself.
  var isClosedWeek = win.weekStart !== getCurrentWeekStart_();
  var currentWeekFileNames = {};
  if (isClosedWeek) {
    try {
      var curParent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
      var curIt = curParent.getFoldersByName(currentWeekWindow_().label);
      if (curIt.hasNext()) {
        var curFiles = curIt.next().getFiles();
        while (curFiles.hasNext()) {
          var cf = curFiles.next();
          if (!cf.isTrashed()) currentWeekFileNames[cf.getName()] = true;
        }
      }
    } catch (e) { /* current week folder not readable — fall back to old behavior */ }
  }

  var parent;
  try {
    parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
  } catch (e) {
    report.error = 'Cannot open the archive parent folder: ' + e.toString();
    log_('WeeklyArchive: ' + report.error);
    return report;
  }

  // Find-or-create the dated folder. getFoldersByName is exact-match, which is
  // what we want — two folders with the same label would split a week's history.
  var target = null;
  var it = parent.getFoldersByName(win.label);
  if (it.hasNext()) {
    target = it.next();
    report.folderExisted = true;
  } else {
    target = parent.createFolder(win.label);
    report.folderExisted = false;
    log_('WeeklyArchive: created folder "' + win.label + '"');
  }
  report.folderId = target.getId();

  // Index what is already archived so re-runs are cheap and late arrivals win.
  var existing = {};
  var exIt = target.getFiles();
  while (exIt.hasNext()) {
    var ex = exIt.next();
    if (ex.isTrashed()) continue;
    existing[ex.getName()] = { file: ex, updated: ex.getLastUpdated().getTime() };
  }

  // Gather candidates from EVERY source folder before copying anything.
  //
  // During a fleet migration the two folders are both live: v2.0.7+ agents write
  // to the newly-configured folder while older agents still write to the folder
  // compiled into their binary. Scanning only one would silently archive half the
  // fleet — and the half it missed would read as "never reported". So scan both
  // and keep the NEWEST instance of each filename, whichever folder it came from.
  // That also makes the migration self-healing: as each agent updates, its file
  // simply starts arriving from the other folder and the newest still wins.
  var sourceIds = archiveSourceFolderIds_();
  report.sourcesScanned = [];
  var candidates = {};   // fileName -> { file, updated, sourceId }

  for (var s = 0; s < sourceIds.length; s++) {
    var sid = sourceIds[s];
    var srcFolder;
    try {
      srcFolder = DriveApp.getFolderById(sid);
    } catch (e) {
      report.sourcesScanned.push({ folderId: sid, ok: false, error: e.toString() });
      log_('WeeklyArchive: cannot open source folder ' + sid + ' — ' + e.toString());
      continue;
    }
    var seenHere = 0;
    // getFiles() lists only direct children, never subfolders — so when the
    // upload folder IS the archive parent, the dated folders we create are not
    // re-scanned and cannot be copied into themselves.
    var sIt = srcFolder.getFiles();
    while (sIt.hasNext()) {
      var sf = sIt.next();
      if (sf.isTrashed()) continue;
      var sfn = sf.getName();
      if (!/_claude_(daily|session)\.json$/i.test(sfn)) continue;
      seenHere++;
      var upd = sf.getLastUpdated().getTime();
      var held = candidates[sfn];
      if (!held || upd > held.updated) {
        candidates[sfn] = { file: sf, updated: upd, sourceId: sid };
      }
    }
    report.sourcesScanned.push({
      folderId: sid, ok: true, folderName: srcFolder.getName(), reportFiles: seenHere
    });
  }

  var fileNames = Object.keys(candidates);
  for (var n = 0; n < fileNames.length; n++) {
    if (Date.now() - started > ARCHIVE_TIME_BUDGET_MS) {
      report.timedOut = true;
      report.remainingAfterTimeout = fileNames.length - n;
      log_('WeeklyArchive: hit the time budget with ' + report.remainingAfterTimeout +
           ' file(s) left — the next daily run resumes where this stopped');
      break;
    }
    var fn = fileNames[n];
    var cand = candidates[fn];
    var f = cand.file;
    var srcUpdated = cand.updated;
    var prior = existing[fn];

    if (prior) {
      // Fixed 2026-07-30: a newer source file no longer automatically means
      // "genuine late arrival for THIS week" — it might just be today's ordinary
      // upload, now that the current week has its own folder to go to instead.
      // If this person already has a file there, they've moved on; leave their
      // entry in this CLOSED week exactly as it was rather than overwriting a
      // real historical record with content that belongs to the new week.
      if (currentWeekFileNames[fn]) { report.movedToCurrentWeek.push(fn); continue; }
      // Only replace when the live file is genuinely newer — a late reporter.
      if (srcUpdated <= prior.updated + 1000) { report.skipped.push(fn); continue; }
      try {
        prior.file.setTrashed(true);
        f.makeCopy(fn, target);
        report.refreshed.push(fn);
      } catch (e) {
        report.failed.push({ file: fn, error: e.toString() });
      }
      continue;
    }

    try {
      f.makeCopy(fn, target);
      report.copied.push(fn);
    } catch (e) {
      report.failed.push({ file: fn, error: e.toString() });
    }
  }

  report.summary = {
    newlyCopied: report.copied.length,
    refreshedFromLateUploads: report.refreshed.length,
    alreadyCurrent: report.skipped.length,
    frozenBecauseMovedToCurrentWeek: report.movedToCurrentWeek.length,
    failures: report.failed.length,
    distinctReportFiles: fileNames.length
  };
  log_('WeeklyArchive "' + win.label + '": ' + report.summary.newlyCopied + ' copied, ' +
       report.summary.refreshedFromLateUploads + ' refreshed, ' +
       report.summary.alreadyCurrent + ' unchanged, ' +
       report.summary.frozenBecauseMovedToCurrentWeek + ' frozen (moved to current week), ' +
       report.summary.failures + ' failed');
  return report;
}

// Daily trigger entry. Snapshots the last completed week, and keeps refreshing
// it for ARCHIVE_GRACE_DAYS so machines that boot mid-week are still captured.
// Public (no requireAdmin_) so the scheduler can run it with no user session.
function runWeeklyArchiveSnapshot() {
  var win = lastCompletedWeekWindow_();
  var endMs = new Date(win.weekEnd + 'T23:59:59Z').getTime();
  var daysSinceClose = (Date.now() - endMs) / 86400000;

  if (daysSinceClose > ARCHIVE_GRACE_DAYS) {
    // Week is final. Nothing to add, and re-copying would churn Drive daily.
    return { skipped: true, reason: 'week "' + win.label + '" closed ' +
             Math.round(daysSinceClose) + ' days ago, past the ' + ARCHIVE_GRACE_DAYS +
             '-day grace window', period: win };
  }
  return snapshotWeeklyReports(win.weekStart, win.weekEnd);
}

function isWeeklyArchiveTriggerInstalled() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'runWeeklyArchiveSnapshot') return true;
  }
  return false;
}

function ensureWeeklyArchiveTrigger_() {
  if (isWeeklyArchiveTriggerInstalled()) return false;
  // Daily at 02:00 script-tz — after the Monday 00:00 generation window opens,
  // and it re-runs every day so late uploads still land in the right week.
  ScriptApp.newTrigger('runWeeklyArchiveSnapshot')
    .timeBased().everyDays(1).atHour(2).create();
  log_('WeeklyArchive: daily snapshot trigger installed (02:00 ' +
       (Session.getScriptTimeZone() || 'Asia/Kolkata') + ')');
  return true;
}

function installWeeklyArchiveTrigger() {
  requireAdmin_();
  var created = ensureWeeklyArchiveTrigger_();
  return { success: true, created: created,
           message: created ? 'Daily archive trigger installed' : 'Already installed' };
}

function uninstallWeeklyArchiveTrigger() {
  requireAdmin_();
  var triggers = ScriptApp.getProjectTriggers();
  var removed = 0;
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'runWeeklyArchiveSnapshot') {
      ScriptApp.deleteTrigger(triggers[i]); removed++;
    }
  }
  return { success: true, removed: removed };
}

// List what has actually been archived, newest week first. This is the index
// that a date-range report search reads.
function listArchivedWeeks() {
  requireAdmin_();
  var out = [];
  try {
    var parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
    var it = parent.getFolders();
    while (it.hasNext()) {
      var f = it.next();
      if (f.isTrashed()) continue;
      if (/^__write_probe_/.test(f.getName())) continue;
      var count = 0;
      var fi = f.getFiles();
      while (fi.hasNext()) { if (!fi.next().isTrashed()) count++; }
      out.push({
        folderName: f.getName(),
        folderId: f.getId(),
        fileCount: count,
        developerCount: Math.floor(count / 2), // daily + session per developer
        createdIso: f.getDateCreated().toISOString(),
        url: f.getUrl()
      });
    }
  } catch (e) {
    return { error: e.toString(), parentFolderId: WEEKLY_ARCHIVE_PARENT_ID };
  }
  out.sort(function(a, b) { return b.createdIso.localeCompare(a.createdIso); });
  return { parentFolderId: WEEKLY_ARCHIVE_PARENT_ID, weeks: out, weekCount: out.length };
}

// ================================================================
// v5.4 — REPORT SEARCH BY DATE RANGE
// ================================================================
// Requirement 3: "Provide a Date Range filter to search reports for a specific
// period", and removed users' reports stay searchable for their retention window.
//
// Implementation note on WHY this does not parse folder names. The archive names
// its folders "July 20-26 2026" via formatWeekLabel_. Parsing that back into
// dates is ambiguous and locale-sensitive (and breaks outright on a month
// boundary, e.g. "June 29-July 5 2026"). Instead this walks the weeks that
// overlap the requested range and asks formatWeekLabel_ for each label — the
// exact same function that created the folders. Lookup is then an exact-name
// match, so it cannot drift from the writer.
var SEARCH_MAX_WEEKS = 110;          // ~2 years; guards against a runaway range
var SEARCH_TIME_BUDGET_MS = 4 * 60 * 1000;

// The Monday that starts the week containing the given yyyy-MM-dd date.
// Anchored at UTC noon like the rest of the week maths here, so a DST or
// offset boundary cannot shift the result by a day.
function mondayOfIso_(iso) {
  var tz = Session.getScriptTimeZone() || 'Asia/Kolkata';
  var p = String(iso).split('-');
  var d = new Date(Date.UTC(parseInt(p[0], 10), parseInt(p[1], 10) - 1, parseInt(p[2], 10), 12, 0, 0));
  var dayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  var dow = dayMap[Utilities.formatDate(d, tz, 'EEE')];
  d.setUTCDate(d.getUTCDate() + ((dow === 0) ? -6 : 1 - dow));
  return Utilities.formatDate(d, tz, 'yyyy-MM-dd');
}

function isIsoDateOnly_(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(s || '').trim()) &&
         !isNaN(new Date(String(s).trim() + 'T12:00:00Z').getTime());
}

// Turn a report filename back into a developer name.
// "Hitarth_Desai_claude_daily.json" -> { developer: 'Hitarth_Desai', type: 'daily' }
function parseReportFileName_(fileName) {
  var m = String(fileName || '').match(/^(.*)_claude_(daily|session)\.json$/i);
  if (!m) return null;
  return { developer: m[1], type: m[2].toLowerCase() };
}

// startIso / endIso: 'yyyy-MM-dd' inclusive. developerFilter: optional substring.
function searchReportsByDateRange(startIso, endIso, developerFilter) {
  requireAdmin_();
  var started = Date.now();

  var start = String(startIso || '').trim();
  var end   = String(endIso   || '').trim();
  if (!isIsoDateOnly_(start) || !isIsoDateOnly_(end)) {
    return { error: 'Both dates must be yyyy-MM-dd (for example 2026-07-01).',
             received: { startIso: startIso, endIso: endIso } };
  }
  if (start > end) { var swap = start; start = end; end = swap; }

  var filter = String(developerFilter || '').trim().toLowerCase();
  var out = {
    requested: { startIso: start, endIso: end, developerFilter: filter || null },
    weeks: [], weeksWithNoArchive: [],
    summary: {}, truncated: false
  };

  var parent;
  try {
    parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
    out.searchedIn = parent.getName();
  } catch (e) {
    return { error: 'Cannot open the reports folder: ' + e.toString(),
             folderId: WEEKLY_ARCHIVE_PARENT_ID };
  }

  // Walk every Monday-start week that overlaps the requested range. A range of
  // a single day still returns the whole week containing it, because that is the
  // granularity the reports are archived at — stated in the response so the
  // caller is never misled about what a match means.
  var cursor = mondayOfIso_(start);
  var lastMonday = mondayOfIso_(end);
  var labels = [];
  var guard = 0;
  while (cursor <= lastMonday && guard < SEARCH_MAX_WEEKS) {
    var p = cursor.split('-');
    var anchor = new Date(Date.UTC(parseInt(p[0], 10), parseInt(p[1], 10) - 1, parseInt(p[2], 10), 12, 0, 0));
    anchor.setUTCDate(anchor.getUTCDate() + 6);
    var weekEnd = Utilities.formatDate(anchor, Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd');
    labels.push({ weekStart: cursor, weekEnd: weekEnd, label: formatWeekLabel_(cursor, weekEnd) });
    anchor.setUTCDate(anchor.getUTCDate() + 1); // -> next Monday
    cursor = Utilities.formatDate(anchor, Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd');
    guard++;
  }
  if (guard >= SEARCH_MAX_WEEKS) {
    out.truncated = true;
    out.truncationNote = 'Range covers more than ' + SEARCH_MAX_WEEKS +
      ' weeks; only the first ' + SEARCH_MAX_WEEKS + ' were searched.';
  }

  var totalFiles = 0;
  var developersSeen = {};

  for (var i = 0; i < labels.length; i++) {
    if (Date.now() - started > SEARCH_TIME_BUDGET_MS) {
      out.truncated = true;
      out.truncationNote = 'Stopped after ' + i + ' of ' + labels.length +
        ' weeks to stay inside the execution limit. Narrow the range.';
      break;
    }
    var wk = labels[i];
    var it = parent.getFoldersByName(wk.label);
    if (!it.hasNext()) { out.weeksWithNoArchive.push(wk.label); continue; }

    var folder = it.next();
    var files = [];
    var fIt = folder.getFiles();
    while (fIt.hasNext()) {
      var f = fIt.next();
      if (f.isTrashed()) continue;
      var meta = parseReportFileName_(f.getName());
      if (!meta) continue;
      if (filter && meta.developer.toLowerCase().indexOf(filter) === -1) continue;
      developersSeen[meta.developer] = true;
      totalFiles++;
      files.push({
        developer: meta.developer,
        type: meta.type,
        fileName: f.getName(),
        url: f.getUrl(),
        sizeBytes: f.getSize(),
        lastModified: f.getLastUpdated().toISOString()
      });
    }
    files.sort(function(a, b) {
      if (a.developer !== b.developer) return a.developer.localeCompare(b.developer);
      return a.type.localeCompare(b.type);
    });
    // A week folder that exists but matched nothing under a developer filter is
    // reported with an empty list rather than omitted, so the caller can tell
    // "no archive for that week" apart from "that person did not report".
    out.weeks.push({
      label: wk.label, weekStart: wk.weekStart, weekEnd: wk.weekEnd,
      folderUrl: folder.getUrl(), folderId: folder.getId(),
      developerCount: Object.keys(files.reduce(function(acc, x) { acc[x.developer] = 1; return acc; }, {})).length,
      fileCount: files.length,
      files: files
    });
  }

  var devList = Object.keys(developersSeen).sort();
  out.summary = {
    weeksSearched: labels.length,
    weeksWithReports: out.weeks.length,
    weeksMissing: out.weeksWithNoArchive.length,
    totalFiles: totalFiles,
    distinctDevelopers: devList.length,
    developers: devList
  };
  out.granularityNote = 'Reports are archived per Mon-Sun week, so results cover every week ' +
    'that OVERLAPS the requested dates — not a day-by-day slice. Each file itself contains the ' +
    'developer\'s full usage history, so a specific day can be filtered from the file contents.';
  if (out.summary.weeksWithReports === 0) {
    out.verdict = 'No archived reports found in that range. Weekly folders only exist from the date ' +
      'the archive was first run onward — earlier periods were never captured.';
  } else {
    out.verdict = 'Found ' + totalFiles + ' report file(s) for ' + devList.length +
      ' developer(s) across ' + out.weeks.length + ' week(s).';
  }
  return out;
}

// ---- Editor-runnable wrapper (Run cannot pass arguments) ----
// Edit these three, then Run logReportSearch.
var SEARCH_FROM = '2026-07-01';
var SEARCH_TO   = '2026-07-31';
var SEARCH_DEVELOPER = '';   // '' = everyone, or e.g. 'Hitarth'

function logReportSearch() {
  Logger.log(JSON.stringify(
    searchReportsByDateRange(SEARCH_FROM, SEARCH_TO, SEARCH_DEVELOPER), null, 2));
}

function logArchiveAccessCheck() {
  Logger.log(JSON.stringify(checkWeeklyArchiveAccess(), null, 2));
}

function logArchiveSnapshotNow() {
  Logger.log(JSON.stringify(runWeeklyArchiveSnapshot(), null, 2));
}

function logArchivedWeeks() {
  Logger.log(JSON.stringify(listArchivedWeeks(), null, 2));
}

// ================================================================
// v5.3 — LIVE REPORT MIRROR
// ================================================================
// Requirement: the reports must appear in the nominated Drive folder
// (WEEKLY_ARCHIVE_PARENT_ID), not only in the Shared Drive the agents write to.
//
// The agents cannot write there themselves. They authenticate as a service
// account, and a service account has no Drive storage allocation, so it cannot
// OWN a file — which is what creating one in an ordinary folder requires. Inside
// a Shared Drive the drive owns the files, which is why the current setup works.
// Granting the service account Editor does not change this; ownership and
// permission are different things.
//
// THIS script, however, executes as a real user with real storage. So the server
// mirrors the files instead. The destination, the filenames and the content are
// identical to a direct upload; only the writer differs. It also works for every
// agent on every version — including the dormant machines that will never
// self-update — which a client-side change could never achieve.
//
// Runs hourly. The dated weekly folders are produced separately by
// snapshotWeeklyReports and are unaffected.
var MIRROR_TIME_BUDGET_MS = 4 * 60 * 1000;

function syncLatestReportsToReportsFolder() {
  var started = Date.now();
  var report = { copied: [], refreshed: [], skipped: [], failed: [], timedOut: false };

  var dest;
  try {
    dest = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
    report.destinationFolder = dest.getName();
  } catch (e) {
    report.error = 'Cannot open the reports folder: ' + e.toString();
    log_('ReportMirror: ' + report.error);
    return report;
  }

  // Index what is already mirrored at the TOP LEVEL of the destination.
  // getFiles() never descends into the dated subfolders, so archived copies are
  // not mistaken for mirrored ones.
  var existing = {};
  var exIt = dest.getFiles();
  while (exIt.hasNext()) {
    var ex = exIt.next();
    if (ex.isTrashed()) continue;
    if (!/_claude_(daily|session)\.json$/i.test(ex.getName())) continue;
    existing[ex.getName()] = { file: ex, updated: ex.getLastUpdated().getTime() };
  }

  // Read from wherever the agents actually write. Deliberately reuses the archive's
  // source list so a future move to a Shared Drive folder needs no change here.
  var sourceIds = archiveSourceFolderIds_().filter(function(id) {
    return id !== WEEKLY_ARCHIVE_PARENT_ID; // never mirror the folder onto itself
  });
  report.sourcesScanned = [];
  var candidates = {};

  for (var s = 0; s < sourceIds.length; s++) {
    var sid = sourceIds[s], srcFolder;
    try {
      srcFolder = DriveApp.getFolderById(sid);
    } catch (e) {
      report.sourcesScanned.push({ folderId: sid, ok: false, error: e.toString() });
      continue;
    }
    var n = 0;
    var sIt = srcFolder.getFiles();
    while (sIt.hasNext()) {
      var sf = sIt.next();
      if (sf.isTrashed()) continue;
      var sfn = sf.getName();
      if (!/_claude_(daily|session)\.json$/i.test(sfn)) continue;
      n++;
      var upd = sf.getLastUpdated().getTime();
      if (!candidates[sfn] || upd > candidates[sfn].updated) {
        candidates[sfn] = { file: sf, updated: upd };
      }
    }
    report.sourcesScanned.push({ folderId: sid, ok: true, folderName: srcFolder.getName(), reportFiles: n });
  }

  var names = Object.keys(candidates);
  for (var i = 0; i < names.length; i++) {
    if (Date.now() - started > MIRROR_TIME_BUDGET_MS) {
      report.timedOut = true;
      report.remainingAfterTimeout = names.length - i;
      log_('ReportMirror: time budget reached, ' + report.remainingAfterTimeout +
           ' file(s) deferred to the next hourly run');
      break;
    }
    var fn = names[i];
    var cand = candidates[fn];
    var prior = existing[fn];

    if (prior) {
      // A mirrored copy's timestamp is its copy time, which is always later than
      // the source it came from. So "source is newer" reliably means the agent has
      // uploaded again since the last mirror.
      if (cand.updated <= prior.updated + 1000) { report.skipped.push(fn); continue; }
      try {
        prior.file.setTrashed(true);
        cand.file.makeCopy(fn, dest);
        report.refreshed.push(fn);
      } catch (e) {
        report.failed.push({ file: fn, error: e.toString() });
      }
      continue;
    }
    try {
      cand.file.makeCopy(fn, dest);
      report.copied.push(fn);
    } catch (e) {
      report.failed.push({ file: fn, error: e.toString() });
    }
  }

  report.summary = {
    newlyMirrored: report.copied.length,
    updated: report.refreshed.length,
    alreadyCurrent: report.skipped.length,
    failures: report.failed.length,
    distinctReportFiles: names.length
  };
  log_('ReportMirror -> "' + report.destinationFolder + '": ' + report.summary.newlyMirrored +
       ' new, ' + report.summary.updated + ' updated, ' + report.summary.alreadyCurrent +
       ' unchanged, ' + report.summary.failures + ' failed');

  // Fixed 2026-07-30: also keep the CURRENT week's dated folder in sync, using
  // the SAME candidates already scanned above — no extra Drive listing needed.
  // Without this, today's uploads had nowhere to land except the previous
  // (closed) week's folder, which is what made "July 20-26 2026" keep absorbing
  // this week's activity days after that period actually ended.
  report.currentWeekFolder = snapshotIntoWeekFolder_(currentWeekWindow_(), candidates, started);

  // v5.5: on-demand pulls ride the same hourly job. They are matched by a
  // different filename pattern and land in their own folder, so they never mix
  // with the weekly compliance record.
  try { report.onDemand = syncOnDemandReports_(); }
  catch (e) { report.onDemand = { error: e.toString() }; }

  return report;
}

// Copies the given {fileName: {file, updated}} candidates into the dated
// folder for `win` ({weekStart, weekEnd, label}), creating it if needed.
// Shared by the hourly mirror (current week, using its already-scanned
// candidates) and the daily archive catch-up (completed week, its own scan).
function snapshotIntoWeekFolder_(win, candidates, startedAt) {
  var out = { label: win.label, copied: [], refreshed: [], skipped: [], failed: [], timedOut: false };
  var parent;
  try {
    parent = DriveApp.getFolderById(WEEKLY_ARCHIVE_PARENT_ID);
  } catch (e) {
    out.error = 'Cannot open the archive parent folder: ' + e.toString();
    return out;
  }

  var target;
  var it = parent.getFoldersByName(win.label);
  if (it.hasNext()) { target = it.next(); out.folderExisted = true; }
  else { target = parent.createFolder(win.label); out.folderExisted = false; }
  out.folderId = target.getId();

  var existing = {};
  var exIt = target.getFiles();
  while (exIt.hasNext()) {
    var ex = exIt.next();
    if (ex.isTrashed()) continue;
    existing[ex.getName()] = { file: ex, updated: ex.getLastUpdated().getTime() };
  }
  out.existingFileNames = Object.keys(existing);

  var names = Object.keys(candidates);
  for (var i = 0; i < names.length; i++) {
    if (Date.now() - startedAt > MIRROR_TIME_BUDGET_MS) {
      out.timedOut = true;
      break;
    }
    var fn = names[i];
    var cand = candidates[fn];
    var prior = existing[fn];
    if (prior) {
      if (cand.updated <= prior.updated + 1000) { out.skipped.push(fn); continue; }
      try {
        prior.file.setTrashed(true);
        cand.file.makeCopy(fn, target);
        out.refreshed.push(fn);
      } catch (e) {
        out.failed.push({ file: fn, error: e.toString() });
      }
      continue;
    }
    try {
      cand.file.makeCopy(fn, target);
      out.copied.push(fn);
    } catch (e) {
      out.failed.push({ file: fn, error: e.toString() });
    }
  }

  log_('CurrentWeekSync -> "' + win.label + '": ' + out.copied.length + ' new, ' +
       out.refreshed.length + ' updated, ' + out.skipped.length + ' unchanged, ' +
       out.failed.length + ' failed');
  return out;
}

function isLatestSyncTriggerInstalled() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'syncLatestReportsToReportsFolder') return true;
  }
  return false;
}

function ensureLatestSyncTrigger_() {
  if (isLatestSyncTriggerInstalled()) return false;
  ScriptApp.newTrigger('syncLatestReportsToReportsFolder').timeBased().everyHours(1).create();
  log_('ReportMirror: hourly sync trigger installed');
  return true;
}

function installLatestSyncTrigger() {
  requireAdmin_();
  var created = ensureLatestSyncTrigger_();
  return { success: true, created: created,
           message: created ? 'Hourly report mirror installed' : 'Already installed' };
}

function uninstallLatestSyncTrigger() {
  requireAdmin_();
  var triggers = ScriptApp.getProjectTriggers();
  var removed = 0;
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'syncLatestReportsToReportsFolder') {
      ScriptApp.deleteTrigger(triggers[i]); removed++;
    }
  }
  return { success: true, removed: removed };
}

// Run this ONCE: installs the hourly trigger and does the first sync immediately
// so the folder is populated now rather than up to an hour from now.
function logEnableReportMirror() {
  requireAdmin_();
  var out = { triggerCreated: ensureLatestSyncTrigger_() };
  out.firstRun = syncLatestReportsToReportsFolder();
  Logger.log(JSON.stringify(out, null, 2));
}

function logSyncLatestReports() {
  Logger.log(JSON.stringify(syncLatestReportsToReportsFolder(), null, 2));
}

// ================================================================
// DASHBOARD LOAD DIAGNOSTIC + CACHE WARMER
// ================================================================
// "INITIALIZING OPERATIONS CENTER..." forever means the page HTML was served
// (doGet worked) but the follow-up getDashboardData() call never came back.
// There are only three real causes, and this tells them apart:
//
//   1. The build is simply slow — a big ComplianceLog, a large roster, or the
//      script being busy serving ~77 agents polling every 60 seconds.
//   2. The payload is too large to CACHE. getDashboardData swallows that failure
//      and logs 'Cache skip', so every single page load silently repeats the full
//      uncached build. That turns one slow load into permanently slow loads.
//   3. It exceeds the 6-minute execution ceiling and is killed, in which case the
//      browser's success handler never fires and the spinner spins forever.
//
// Running this also WARMS the cache, so the very next browser load is served
// from cache and returns immediately. Use it as the practical unblock.
function diagnoseDashboardLoad() {
  requireAdmin_();
  var out = {};

  var t0 = Date.now();
  var data = getDashboardData_uncached_();
  out.buildMs = Date.now() - t0;

  var t1 = Date.now();
  var json = JSON.stringify(data);
  out.stringifyMs = Date.now() - t1;
  out.payloadBytes = json.length;
  out.payloadKB = Math.round(json.length / 1024);
  out.cacheChunksNeeded = Math.ceil(json.length / 50000);

  out.counts = {
    registeredDevelopers: (data.registeredDevelopers || []).length,
    removedUsers:         (data.removedUsers || []).length,
    activeUsers:          (data.activeUsers || []).length,
    weeks:                (data.weeks || []).length,
    recentUploads:        (data.recentUploads || []).length,
    triggerQueue:         (data.triggerQueue || []).length,
    complianceGridRows:   Object.keys(data.complianceGrid || {}).length
  };

  // Which single section is the heaviest? Usually recentUploads or complianceByWeek.
  out.sectionBytes = {};
  ['activeUsers', 'complianceByWeek', 'complianceGrid', 'recentUploads',
   'registeredDevelopers', 'removedUsers'].forEach(function(k) {
    try { out.sectionBytes[k] = JSON.stringify(data[k] || null).length; } catch (e) {}
  });

  // Now actually warm the cache and report honestly whether it stuck.
  var cache = CacheService.getScriptCache();
  try {
    chunkedCachePut(cache, 'dashboardData', json, 300);
    var readBack = chunkedCacheGet(cache, 'dashboardData');
    out.cacheWritten = !!readBack;
    out.cacheReadBackBytes = readBack ? readBack.length : 0;
    out.cacheIntact = !!readBack && readBack.length === json.length;
  } catch (e) {
    out.cacheWritten = false;
    out.cacheError = e.toString();
  }
  cache.put('lastModified', String(Date.now()), 3600);

  if (!out.cacheWritten || !out.cacheIntact) {
    out.verdict = 'CACHE IS FAILING (payload ' + out.payloadKB + ' KB). Every page load therefore ' +
      'rebuilds from scratch, which is why it never finishes. This needs the payload reduced — ' +
      'the heaviest sections are listed in sectionBytes.';
  } else if (out.buildMs > 120000) {
    out.verdict = 'VERY SLOW BUILD (' + Math.round(out.buildMs / 1000) + 's). Close to the 6-minute ' +
      'execution ceiling, past which the browser spinner hangs forever. Cache is now warm, so reload ' +
      'the dashboard and it should appear at once — but this needs reducing.';
  } else if (out.buildMs > 30000) {
    out.verdict = 'SLOW BUILD (' + Math.round(out.buildMs / 1000) + 's) but the cache is warm now. ' +
      'Reload the dashboard — it should load immediately. Expect another slow load when the 5-minute ' +
      'cache expires.';
  } else {
    out.verdict = 'HEALTHY: built in ' + out.buildMs + 'ms, cached ' + out.payloadKB + ' KB ' +
      'successfully. If the browser still hangs, the fault is client-side — hard-refresh with ' +
      'Ctrl+Shift+R, or try an incognito window to rule out stale cached JavaScript.';
  }
  return out;
}

function logDashboardLoad() {
  Logger.log(JSON.stringify(diagnoseDashboardLoad(), null, 2));
}

// -------------------- PAUSE / RESUME --------------------

function isDeveloperPaused_(ss, name) {
  var sheet = ss.getSheetByName('PausedDevelopers');
  if (!sheet) return false;
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim().toLowerCase() === name.trim().toLowerCase()) {
      return true;
    }
  }
  return false;
}

function getPausedDevelopersMap_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('PausedDevelopers');
  var map = {};
  if (!sheet) return map;
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0]) {
      var n = String(data[i][0]).trim().toLowerCase();
      var ts = data[i][1];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
      else ts = String(ts || '');
      map[n] = { pausedAt: ts, pausedBy: String(data[i][2] || '') };
    }
  }
  return map;
}

function getPausedDevelopersList() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('PausedDevelopers');
  if (!sheet) return [];
  var data = sheet.getDataRange().getValues();
  var result = [];
  for (var i = 1; i < data.length; i++) {
    if (data[i][0]) {
      var ts = data[i][1];
      if (ts && typeof ts.getTime === 'function') ts = ts.toISOString();
      else ts = String(ts || '');
      result.push({
        name: String(data[i][0]).trim(),
        pausedAt: ts,
        pausedBy: String(data[i][2] || '')
      });
    }
  }
  return result;
}

function adminPauseDeveloper(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  name = name.trim();
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ensurePausedDevelopersSheet_();
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.toLowerCase()) {
        return { success: false, error: name + ' is already paused' };
      }
    }

    var who = '';
    try { who = Session.getActiveUser().getEmail(); } catch (e) { who = 'admin'; }

    sheet.appendRow([name, new Date().toISOString(), who]);
    log_('PausedDevelopers: paused ' + name + ' by ' + who);
    invalidateCache_();
  } finally {
    lock.releaseLock();
  }
  // v3: outside the lock — Drive iteration is slow and must not starve
  // other executions waiting on the script lock.
  var deleted = deleteUploaderDriveFiles_(name);
  return { success: true, driveFilesDeleted: deleted };
}

function adminResumeDeveloper(name) {
  requireAdmin_();
  if (!name || !name.trim()) return { success: false, error: 'Name is required' };
  // v5: a removed user sits in PausedDevelopers precisely so their agent stops
  // uploading. Resuming them without clearing Removed first would restart the
  // uploads while they are still absent from the roster. The UI cannot reach
  // this path (removed users only expose Restore / Purge), but a direct call
  // could — adminRestoreUser clears the status before it resumes, so it passes.
  var pre = findRosterRow_(name);
  if (pre && normalizeUserStatus_(pre.row[REG_COL_STATUS]) === USER_STATUS.REMOVED) {
    return { success: false, error: name + ' is removed — use Restore instead of Resume' };
  }
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('PausedDevelopers');
    if (!sheet) return { success: false, error: name + ' is not paused' };
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === name.trim().toLowerCase()) {
        sheet.deleteRow(i + 1);
        log_('PausedDevelopers: resumed ' + name);
        invalidateCache_();
        return { success: true };
      }
    }
    return { success: false, error: name + ' is not paused' };
  } finally {
    lock.releaseLock();
  }
}

// -------------------- SETTINGS --------------------

// v2: schema version this code expects. Bump when ComplianceLog / HeartbeatLog
// / TriggerQueue / RegisteredDevelopers columns are added or changed. The
// `getSchemaInfo` endpoint surfaces this on the Health page.
var SHEET_SCHEMA_VERSION = 'v5.0';

function ensureSettingsSheet_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Settings');
  if (!sheet) {
    sheet = ss.insertSheet('Settings');
    sheet.appendRow(['Key', 'Value']);
    sheet.getRange(1, 1, 1, 2).setFontWeight('bold');
    sheet.appendRow(['uploadFrequency', 'weekly']);
  }
  // v2: record the schema version on every doGet so a freshly cloned sheet
  // gets stamped automatically. Idempotent — only writes if missing/older.
  try {
    var data = sheet.getDataRange().getValues();
    var schemaRowIdx = -1;
    var currentVer = '';
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === 'schemaVersion') { schemaRowIdx = i + 1; currentVer = String(data[i][1]).trim(); break; }
    }
    if (schemaRowIdx === -1) {
      sheet.appendRow(['schemaVersion', SHEET_SCHEMA_VERSION]);
    } else if (currentVer !== SHEET_SCHEMA_VERSION) {
      sheet.getRange(schemaRowIdx, 2).setValue(SHEET_SCHEMA_VERSION);
    }
  } catch (e) { /* non-fatal */ }
  return sheet;
}

// v2: expose schema state to the dashboard Health page
function getSchemaInfo() {
  ensureSettingsSheet_();
  return {
    expectedVersion: SHEET_SCHEMA_VERSION,
    storedVersion: getSetting_('schemaVersion', ''),
    methodologyVersion: 'v2.0'
  };
}

function getSetting_(key, defaultVal) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Settings');
  if (!sheet) return defaultVal;
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === key) return String(data[i][1]).trim();
  }
  return defaultVal;
}

function getUploadFrequency() {
  return getSetting_('uploadFrequency', 'weekly');
}

function normalizeUploadTime_(raw) {
  var text = String(raw == null ? '' : raw).trim();
  if (/^\d{1,2}:\d{2}$/.test(text)) {
    var bits = text.split(':');
    var hh = Math.max(0, Math.min(23, parseInt(bits[0], 10)));
    var mm = Math.max(0, Math.min(59, parseInt(bits[1], 10)));
    return ('0' + hh).slice(-2) + ':' + ('0' + mm).slice(-2);
  }
  var serial = Number(text);
  if (isFinite(serial) && serial >= 0 && serial < 1) {
    var total = Math.round(serial * 24 * 60) % (24 * 60);
    return ('0' + Math.floor(total / 60)).slice(-2) + ':' + ('0' + (total % 60)).slice(-2);
  }
  return '13:00';
}

function getUploadSchedule_() {
  var frequency = getSetting_('uploadFrequency', 'weekly');
  if (['daily', 'weekly', 'monthly'].indexOf(frequency) === -1) frequency = 'weekly';
  var day = getSetting_('globalUploadDay', 'Tuesday');
  var monthDay = parseInt(getSetting_('globalUploadMonthDay', '1'), 10);
  if (!isFinite(monthDay) || monthDay < 1 || monthDay > 31) monthDay = 1;
  return {
    frequency: frequency,
    time: getUploadTimeSetting_('13:00'),
    day: day,
    monthDay: monthDay,
    timeZone: Session.getScriptTimeZone() || 'Asia/Kolkata'
  };
}

function getUploadScheduleCached_() {
  var cache = CacheService.getScriptCache();
  var cached = cache.get('upload_schedule_json');
  if (cached) {
    try { return JSON.parse(cached); } catch (e) {}
  }
  var schedule = getUploadSchedule_();
  cache.put('upload_schedule_json', JSON.stringify(schedule), 300);
  return schedule;
}

function setSettingValue_(sheet, key, value) {
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === key) {
      sheet.getRange(i + 1, 2).setValue(value);
      return;
    }
  }
  sheet.appendRow([key, value]);
}

// Bug found 2026-07-30: writing '00:00' via setSettingValue_ silently produced a
// dashboard schedule of 13:00, not 00:00 — the requirement (Monday 00:00 IST)
// was never actually in effect despite applyWeeklyGenerationDefault_ believing
// it had set it.
//
// Root cause: Sheets auto-detects a plain .setValue('00:00') as a TIME and
// stores the cell as a Date (epoch 1899-12-30 + that time-of-day), not the
// literal string. getSetting_ then does String(dateCell), which yields
// something like "Sat Dec 30 1899 00:00:00 GMT+0530" — a string that matches
// neither of normalizeUploadTime_'s parse branches (HH:mm, or a 0-1 day
// fraction), so it silently fell through to the hardcoded '13:00' default.
// No error was ever thrown; the value just quietly wasn't what was written.
//
// Fix, at both ends:
//  - WRITE: force the cell to plain-text format before setValue, so Sheets can
//    never reinterpret "00:00" as a time type again.
//  - READ: if a cell written by the OLD code path is still Date-typed, recover
//    the real time via Utilities.formatDate instead of String(), and repair the
//    cell back to text so this self-heals without needing a manual sheet edit.
function setTimeSettingValue_(sheet, key, hhmm) {
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === key) {
      var cell = sheet.getRange(i + 1, 2);
      cell.setNumberFormat('@STRING@').setValue(hhmm);
      return;
    }
  }
  var row = sheet.getLastRow() + 1;
  sheet.appendRow([key, hhmm]);
  sheet.getRange(row, 2).setNumberFormat('@STRING@').setValue(hhmm);
}

function getUploadTimeSetting_(defaultVal) {
  var sheet = ensureSettingsSheet_();
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() !== 'globalUploadTime') continue;
    var raw = data[i][1];
    if (raw && typeof raw.getTime === 'function') {
      // A stale Date-typed cell from before this fix. Use Utilities.formatDate
      // with the script timezone — the same pattern every other date/time read
      // in this file uses (getCurrentWeekStart_, formatWeekLabel_, etc.) — rather
      // than raw Date getters, whose local-vs-UTC behavior inside the Apps
      // Script V8 runtime is not worth relying on here.
      var tz = Session.getScriptTimeZone() || 'Asia/Kolkata';
      var fixed = Utilities.formatDate(raw, tz, 'HH:mm');
      setTimeSettingValue_(sheet, 'globalUploadTime', fixed); // self-heal
      log_('Settings: repaired globalUploadTime from a Date-typed cell to "' + fixed + '"');
      return fixed;
    }
    return normalizeUploadTime_(String(raw).trim());
  }
  return normalizeUploadTime_(defaultVal);
}

function setUploadSchedule(schedule) {
  requireAdmin_();
  schedule = schedule || {};
  var frequency = String(schedule.frequency || '').trim();
  if (['daily', 'weekly', 'monthly'].indexOf(frequency) === -1) return { success: false, error: 'Invalid frequency' };
  var time = normalizeUploadTime_(schedule.time);
  var validDays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  var day = String(schedule.day || 'Tuesday');
  if (validDays.indexOf(day) === -1) return { success: false, error: 'Invalid weekly day' };
  var monthDay = parseInt(schedule.monthDay, 10) || 1;
  if (monthDay < 1 || monthDay > 31) return { success: false, error: 'Monthly day must be 1-31' };

  var sheet = ensureSettingsSheet_();
  setSettingValue_(sheet, 'uploadFrequency', frequency);
  setTimeSettingValue_(sheet, 'globalUploadTime', time);
  setSettingValue_(sheet, 'globalUploadDay', day);
  setSettingValue_(sheet, 'globalUploadMonthDay', monthDay);
  invalidateCache_();
  log_('Settings: upload schedule set to ' + JSON.stringify(getUploadSchedule_()));
  return { success: true, schedule: getUploadSchedule_() };
}

function setUploadFrequency(freq) {
  requireAdmin_();
  var valid = ['daily', 'weekly', 'monthly'];
  if (valid.indexOf(freq) === -1) return { success: false, error: 'Invalid frequency. Must be daily, weekly, or monthly.' };
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ensureSettingsSheet_();
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][0]).trim() === 'uploadFrequency') {
      sheet.getRange(i + 1, 2).setValue(freq);
      log_('Settings: uploadFrequency changed to ' + freq);
      invalidateCache_();
      return { success: true };
    }
  }
  sheet.appendRow(['uploadFrequency', freq]);
  log_('Settings: uploadFrequency set to ' + freq);
  invalidateCache_();
  return { success: true };
}

function forceSendUpdateTrigger(name) {
  requireAdmin_(); // v2: was unguarded — allowed any web-app caller to push UPDATE triggers
  if (!name) return { success: false, error: 'No name provided' };
  return adminQueueTrigger(name, 'UPDATE');
}

// v2: bulk-force-update — used by the Version Drift card to upgrade every
// developer whose reported version is behind the latest manifest.
//
// Fixed 2026-07-30: this used to call adminQueueTrigger() once per name in a
// loop, so a 26-person batch acquired and released the whole-script lock 26
// separate times. With ~20 agents heartbeating concurrently (each briefly
// taking the same lock for its own smart-retry/auto-generate check), that
// reliably produced "Lock timeout" partway through — the admin would watch a
// batch of "Force Hot-Patch" clicks succeed for a while then start failing as
// contention built up. adminQueueTriggerBatch takes the lock ONCE for the
// entire list, so a 26-person batch is exactly as lock-safe as a 1-person one.
function forceSendUpdateBatch(names) {
  requireAdmin_();
  if (!Array.isArray(names) || names.length === 0) return { success: false, error: 'No names provided' };
  var result = adminQueueTriggerBatch(names, 'UPDATE');
  // Preserve the response shape the Version Matrix "Force update N outdated"
  // button already expects (success/queued/failed/errors), rather than the
  // queued/skipped shape adminQueueTriggerBatch returns for its other caller.
  var errors = result.skipped.map(function(n) { return n + ': already queued'; });
  return { success: errors.length === 0, queued: result.queued.length, failed: errors.length, errors: errors };
}

// ================================================================
// v5 — UTILITY DISTRIBUTION, USER EMAILS & WEEKLY ADMIN DIGESTS
// ================================================================
// Download URLs live in Script Properties rather than being fetched from the
// release manifest at runtime: getLatestVersion() already dropped its
// UrlFetchApp lookup because the script.external_request scope can only be
// granted through an interactive consent screen, which a headless clasp
// redeploy can never do. Same constraint applies here, same solution.

var DOWNLOAD_PROP_KEYS = {
  windows: 'download_url_windows',
  macos:   'download_url_macos',
  linux:   'download_url_linux'
};

// The System choice offered when adding a user. `platform` maps the choice to
// the download URL that gets embedded in their setup email.
var SYSTEM_OPTIONS = [
  { value: 'Windows (Company)',  platform: 'windows' },
  { value: 'Windows (Personal)', platform: 'windows' },
  { value: 'macOS (Company)',    platform: 'macos'   },
  { value: 'macOS (Personal)',   platform: 'macos'   },
  { value: 'Linux (Company)',    platform: 'linux'   },
  { value: 'Linux (Personal)',   platform: 'linux'   }
];

// Per-execution memo. A mass send to N users would otherwise re-read the same
// four Script Properties per recipient (once for the guard, once more inside
// renderEmailTemplate_), which at fleet scale is hundreds of pointless reads.
// Reset by setUtilityDownloadConfig so a save is visible immediately.
var _downloadCfgMemo = null;

function getUtilityDownloadConfig() {
  if (_downloadCfgMemo) return _downloadCfgMemo;
  var props = PropertiesService.getScriptProperties();
  var cfg = { latestVersion: getLatestVersion(), systemOptions: SYSTEM_OPTIONS, urls: {} };
  Object.keys(DOWNLOAD_PROP_KEYS).forEach(function(platform) {
    cfg.urls[platform] = '';
    try {
      cfg.urls[platform] = String(props.getProperty(DOWNLOAD_PROP_KEYS[platform]) || '').trim();
    } catch (e) {}
  });
  _downloadCfgMemo = cfg;
  return cfg;
}

function setUtilityDownloadConfig(urls) {
  requireAdmin_();
  urls = urls || {};
  var props = PropertiesService.getScriptProperties();
  var saved = {};
  Object.keys(DOWNLOAD_PROP_KEYS).forEach(function(platform) {
    if (urls[platform] === undefined) return;
    var url = String(urls[platform] || '').trim();
    if (url && !/^https:\/\//i.test(url)) {
      throw new Error('Download URL for ' + platform + ' must be an https:// link');
    }
    props.setProperty(DOWNLOAD_PROP_KEYS[platform], url);
    saved[platform] = url;
  });
  _downloadCfgMemo = null; // force a re-read so the save is visible at once
  invalidateCache_();
  log_('Utility download URLs updated: ' + JSON.stringify(saved));
  return { success: true, config: getUtilityDownloadConfig() };
}

// Resolve the right download URL for a user's recorded System. Falls back to
// the Windows URL (the overwhelming majority of the fleet) when the System
// field is blank or unrecognised.
function downloadUrlForSystem_(system) {
  var cfg = getUtilityDownloadConfig();
  var match = null;
  for (var i = 0; i < SYSTEM_OPTIONS.length; i++) {
    if (SYSTEM_OPTIONS[i].value.toLowerCase() === String(system || '').trim().toLowerCase()) {
      match = SYSTEM_OPTIONS[i];
      break;
    }
  }
  if (!match) {
    var s = String(system || '').toLowerCase();
    if (s.indexOf('mac') !== -1)   match = { platform: 'macos' };
    else if (s.indexOf('linux') !== -1) match = { platform: 'linux' };
    else match = { platform: 'windows' };
  }
  return cfg.urls[match.platform] || '';
}

// -------------------- EMAIL TEMPLATES --------------------
// Admin-editable bodies stored in Script Properties. Placeholders are
// substituted per recipient so a single template serves the whole fleet.
// Supported: {{name}} {{firstName}} {{email}} {{system}} {{version}}
//            {{latestVersion}} {{downloadUrl}}

var EMAIL_TEMPLATE_KINDS = ['setup', 'update', 'reminder'];

var DEFAULT_EMAIL_TEMPLATES = {
  setup: {
    subject: 'Action required: install the Claude Usage Uploader',
    body: 'Hi {{firstName}},\n\n' +
      'You have been enrolled in Claude Code usage reporting. Please install the ' +
      'Claude Usage Uploader on your {{system}} machine. It takes about two minutes.\n\n' +
      'Download (v{{latestVersion}}):\n{{downloadUrl}}\n\n' +
      'Steps:\n' +
      '  1. Download the ZIP and RIGHT-CLICK it > Extract All.\n' +
      '     (Do not run anything from inside the ZIP without extracting first.)\n' +
      '  2. In the extracted folder, right-click "Repair-Claude-Uploader.cmd"\n' +
      '     and choose "Run as administrator". Click Yes when Windows asks.\n' +
      '  3. A page opens in your browser. Enter your name exactly as\n' +
      '     "{{name}}" and click Save.\n\n' +
      'That is all. The tool then runs silently in the background and starts itself\n' +
      'at every login. There is no icon and no window — that is normal.\n\n' +
      'Two things to be aware of:\n' +
      '  - Run it from your own Windows login. The background task is registered\n' +
      '    for whoever runs it, so it will not work if someone else runs it for you.\n' +
      '  - Keep the extracted files together in one folder. The tool will not start\n' +
      '    if any of them are moved or deleted.\n\n' +
      'If anything goes wrong, open "install guide.txt" in the same folder, or reply\n' +
      'to this email and attach the file %TEMP%\\claude-uploader.log\n' +
      '(paste %TEMP% into the File Explorer address bar to find it).\n\n' +
      'Thanks,\nSigma Solve Engineering'
  },
  update: {
    subject: 'Please update the Claude Usage Uploader to v{{latestVersion}}',
    body: 'Hi {{firstName}},\n\n' +
      'Your Claude Usage Uploader is running v{{version}}. The current release is ' +
      'v{{latestVersion}}.\n\n' +
      'Download the latest version here:\n{{downloadUrl}}\n\n' +
      'Run the installer over your existing setup — your configuration is preserved ' +
      'and you do not need to re-enter your name.\n\n' +
      'Thanks,\nSigma Solve Engineering'
  },
  reminder: {
    subject: 'Reminder: update your Claude Usage Uploader to v{{latestVersion}}',
    body: 'Hi {{firstName}},\n\n' +
      'This is a reminder that your Claude Usage Uploader (currently v{{version}}) is ' +
      'out of date. The latest version is v{{latestVersion}}.\n\n' +
      'Please update at your earliest convenience:\n{{downloadUrl}}\n\n' +
      'Older versions may stop reporting correctly, which shows up as a compliance ' +
      'gap against your name.\n\n' +
      'Thanks,\nSigma Solve Engineering'
  }
};

// Per-execution memo for the stored (customised) templates, for the same reason
// as _downloadCfgMemo: a mass send resolves the same template once per recipient.
var _templateMemo = {};

function getStoredTemplateMemo_(kind) {
  if (_templateMemo.hasOwnProperty(kind)) return _templateMemo[kind];
  var stored = null;
  try {
    stored = JSON.parse(PropertiesService.getScriptProperties().getProperty('email_tpl_' + kind) || 'null');
  } catch (e) {}
  _templateMemo[kind] = stored;
  return stored;
}

function getEmailTemplates() {
  requireAdmin_();
  var out = {};
  EMAIL_TEMPLATE_KINDS.forEach(function(kind) {
    var stored = getStoredTemplateMemo_(kind);
    out[kind] = {
      subject:   (stored && stored.subject) || DEFAULT_EMAIL_TEMPLATES[kind].subject,
      body:      (stored && stored.body)    || DEFAULT_EMAIL_TEMPLATES[kind].body,
      isCustom:  !!stored,
      defaultSubject: DEFAULT_EMAIL_TEMPLATES[kind].subject,
      defaultBody:    DEFAULT_EMAIL_TEMPLATES[kind].body
    };
  });
  return out;
}

function setEmailTemplate(kind, subject, body) {
  requireAdmin_();
  if (EMAIL_TEMPLATE_KINDS.indexOf(kind) === -1) {
    return { success: false, error: 'Unknown template: ' + kind };
  }
  var s = String(subject || '').trim();
  var b = String(body || '').trim();
  if (!s || !b) return { success: false, error: 'Subject and body are both required' };
  PropertiesService.getScriptProperties()
    .setProperty('email_tpl_' + kind, JSON.stringify({ subject: s, body: b }));
  delete _templateMemo[kind];
  log_('Email template updated: ' + kind);
  return { success: true };
}

function resetEmailTemplate(kind) {
  requireAdmin_();
  if (EMAIL_TEMPLATE_KINDS.indexOf(kind) === -1) {
    return { success: false, error: 'Unknown template: ' + kind };
  }
  PropertiesService.getScriptProperties().deleteProperty('email_tpl_' + kind);
  delete _templateMemo[kind];
  return { success: true };
}

function renderEmailTemplate_(text, user) {
  var latest = getUtilityDownloadConfig().latestVersion; // memoized
  var name = String(user.name || '').trim();
  var vars = {
    '{{name}}':          name.replace(/_/g, ' '),
    '{{firstName}}':     (name.replace(/_/g, ' ').split(/\s+/)[0] || 'there'),
    '{{email}}':         user.email || '',
    '{{system}}':        user.system || 'work',
    '{{version}}':       user.version || 'unknown',
    '{{latestVersion}}': latest,
    '{{downloadUrl}}':   downloadUrlForSystem_(user.system)
  };
  var out = String(text == null ? '' : text);
  Object.keys(vars).forEach(function(token) {
    out = out.split(token).join(vars[token]);
  });
  return out;
}

// ---------- HTML EMAIL RENDERING (v5.5) ----------
// Why this exists: the templates are plain text with hard newlines every ~75
// characters. Mail clients honour those literally, so a sentence written across
// two source lines arrived visibly broken in the middle, with ragged gaps.
//
// This reflows the text: a BLANK line still starts a new paragraph (author
// intent), but a single newline inside a paragraph is treated as a soft wrap and
// joined back into flowing text. Numbered steps, bullets and the bare URL keep
// their own lines, because there the break IS meaningful.
function htmlEsc_(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildEmailHtml_(subject, plainBody) {
  var BRAND = '#0047FB';
  var text = String(plainBody == null ? '' : plainBody).replace(/\r\n/g, '\n');

  // Split on blank lines — those are the author's real paragraph breaks.
  var blocks = text.split(/\n[ \t]*\n/);
  var html = '';

  blocks.forEach(function(block) {
    var lines = block.split('\n').map(function(l) { return l.replace(/\s+$/, ''); })
                     .filter(function(l) { return l.trim() !== ''; });
    if (lines.length === 0) return;

    // A block whose lines are numbered steps or bullets keeps one item per line.
    var isList = lines.every(function(l) { return /^\s*(\d+\.|[-*•])\s+/.test(l); }) ||
                 lines.filter(function(l) { return /^\s*(\d+\.|[-*•])\s+/.test(l); }).length >= 2;

    if (isList) {
      // Lead-in lines BEFORE the first marker ("Steps:", "Two things to be
      // aware of:") carry real meaning and must not be swallowed. Without this
      // they hit the `else if (items.length)` branch with an empty list and
      // were dropped from the delivered mail entirely.
      var leadIn = [];
      var listLines = [];
      var seenMarker = false;
      lines.forEach(function(l) {
        if (/^\s*(\d+\.|[-*•])\s+/.test(l)) seenMarker = true;
        (seenMarker ? listLines : leadIn).push(l);
      });
      if (leadIn.length) {
        html += '<p style="margin:0 0 10px;line-height:1.7;color:#0f172a;font-weight:700">' +
                inlineEmailMarkup_(leadIn.join(' ')) + '</p>';
      }

      var ordered = /^\s*\d+\./.test(listLines[0]);
      // Continuation lines (indented, no marker) belong to the previous item —
      // append them rather than emitting a stray bullet.
      var items = [];
      listLines.forEach(function(l) {
        if (/^\s*(\d+\.|[-*•])\s+/.test(l)) {
          items.push(l.replace(/^\s*(\d+\.|[-*•])\s+/, '').trim());
        } else if (items.length) {
          items[items.length - 1] += ' ' + l.trim();
        }
      });
      html += '<' + (ordered ? 'ol' : 'ul') +
              ' style="margin:0 0 16px;padding-left:22px;color:#334155">' +
        items.map(function(it) {
          return '<li style="margin:0 0 7px;line-height:1.65">' + inlineEmailMarkup_(it) + '</li>';
        }).join('') +
      '</' + (ordered ? 'ol' : 'ul') + '>';
      return;
    }

    // A lone URL on its own — render as a prominent button instead of raw text.
    if (lines.length === 1 && /^https?:\/\/\S+$/.test(lines[0].trim())) {
      var href = lines[0].trim();
      html += '<p style="margin:0 0 20px"><a href="' + htmlEsc_(href) + '"' +
              ' style="display:inline-block;background:' + BRAND + ';color:#ffffff;' +
              'text-decoration:none;font-weight:700;padding:12px 22px;border-radius:8px;' +
              'font-size:15px">Download the Claude Usage Uploader</a></p>';
      return;
    }

    // Ordinary paragraph: join the soft-wrapped lines back into flowing text.
    html += '<p style="margin:0 0 15px;line-height:1.7;color:#334155">' +
            inlineEmailMarkup_(lines.join(' ')) + '</p>';
  });

  return '' +
  '<div style="margin:0;padding:0;background:#f1f5f9">' +
    '<div style="max-width:640px;margin:0 auto;padding:26px 18px">' +
      '<div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">' +
        '<div style="background:linear-gradient(135deg,#0047FB,#0087BD);padding:20px 26px">' +
          '<div style="color:#ffffff;font:700 17px/1.3 Arial,Helvetica,sans-serif">Sigma Solve</div>' +
          '<div style="color:rgba(255,255,255,.85);font:400 12px/1.4 Arial,Helvetica,sans-serif;' +
          'margin-top:3px">Claude Code Usage Reporting</div>' +
        '</div>' +
        '<div style="padding:26px;font:400 15px/1.7 Arial,Helvetica,sans-serif;color:#334155">' +
          html +
        '</div>' +
      '</div>' +
      '<div style="text-align:center;color:#94a3b8;font:400 11px/1.6 Arial,Helvetica,sans-serif;' +
      'padding:14px 8px">This is an automated message from the Sigma Solve Compliance Dashboard.</div>' +
    '</div>' +
  '</div>';
}

// Bolds the things a recipient must not miss, and linkifies bare URLs.
// Deliberately conservative: it only emphasises known key phrases and literal
// filenames/paths, so it can never mangle arbitrary admin-authored wording.
function inlineEmailMarkup_(line) {
  var s = htmlEsc_(line);

  // Bare URLs -> real links (skip ones already inside a button block).
  s = s.replace(/(https?:\/\/[^\s<]+)/g, function(u) {
    return '<a href="' + u + '" style="color:#0047FB;font-weight:600">' + u + '</a>';
  });

  // Literal things the user has to type, click, or find on disk.
  s = s.replace(/(Repair-Claude-Uploader\.cmd|install guide\.txt|service-account-key\.json|%TEMP%\\claude-uploader\.log|%TEMP%)/g,
    '<code style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;' +
    'padding:1px 5px;font:600 13px/1.5 Consolas,Monaco,monospace;color:#0f172a">$1</code>');

  // Key instruction phrases -> bold.
  [
    'Run as administrator', 'Extract All', 'RIGHT-CLICK', 'Right-click',
    'your own Windows login', 'Action required',
    'There is no icon and no window', 'runs silently in the background'
  ].forEach(function(phrase) {
    var esc = htmlEsc_(phrase).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    s = s.replace(new RegExp('(' + esc + ')', 'g'), '<strong style="color:#0f172a">$1</strong>');
  });

  return s;
}

// Single send path for every user-facing email, so quota failures, missing
// addresses and missing download URLs are reported the same way everywhere.
function sendUserEmail_(kind, user, overrideSubject, overrideBody) {
  if (!user || !user.email) return { sent: false, error: 'no email address on file' };
  if (!isValidEmail_(user.email)) return { sent: false, error: 'invalid email address' };

  var stored = getStoredTemplateMemo_(kind);
  var tpl = DEFAULT_EMAIL_TEMPLATES[kind] || DEFAULT_EMAIL_TEMPLATES.setup;

  var subject = overrideSubject || (stored && stored.subject) || tpl.subject;
  var body    = overrideBody    || (stored && stored.body)    || tpl.body;

  subject = renderEmailTemplate_(subject, user);
  body    = renderEmailTemplate_(body, user);

  // A setup/update mail whose download link resolved to nothing is worse than
  // no mail at all — the recipient has nothing to act on. Fail loudly instead.
  if (!downloadUrlForSystem_(user.system)) {
    return { sent: false, error: 'no download URL configured for this system — set one on the Users page' };
  }

  try {
    // v5.5: send as formatted HTML with the plain text kept as the fallback
    // body. The templates are authored as plain text with hard '\n' line breaks
    // at fixed column positions, which is what made the delivered mail wrap
    // mid-sentence and look broken. buildEmailHtml_ reflows those into real
    // paragraphs so sentences stay intact at any window width, and promotes the
    // key instructions to bold.
    GmailApp.sendEmail(user.email, subject, body, {
      htmlBody: buildEmailHtml_(subject, body),
      name: 'Sigma Solve Engineering'
    });
    return { sent: true };
  } catch (e) {
    return { sent: false, error: e.toString() };
  }
}

function sendSetupEmail_(user, overrideSubject, overrideBody) {
  var r = sendUserEmail_('setup', user, overrideSubject, overrideBody);
  log_('Setup email to ' + (user.email || user.name) + ': ' + (r.sent ? 'sent' : 'FAILED — ' + r.error));
  return r;
}

// Re-send the setup / download email to an existing user (Requirement 2b:
// "send a new email containing the latest utility download URL").
function sendSetupEmailToUser(name, overrideSubject, overrideBody) {
  requireAdmin_();
  var user = lookupUserForEmail_(name);
  if (!user) return { success: false, error: name + ' not found' };
  var r = sendSetupEmail_(user, overrideSubject, overrideBody);
  return { success: r.sent, error: r.error || null };
}

// Resolve a roster row into the shape the email templates expect.
function lookupUserForEmail_(name) {
  var hit = findRosterRow_(name);
  if (!hit) return null;
  return {
    name:    String(hit.row[0]).trim(),
    email:   hit.row[REG_COL_EMAIL]  ? String(hit.row[REG_COL_EMAIL]).trim()  : '',
    system:  hit.row[REG_COL_SYSTEM] ? String(hit.row[REG_COL_SYSTEM]).trim() : '',
    version: hit.row[6] ? String(hit.row[6]).trim() : '',
    status:  normalizeUserStatus_(hit.row[REG_COL_STATUS])
  };
}

// -------------------- MASS UPDATE / REMINDER MAIL --------------------
// Requirement 4: mass reminder emails prompting users to update.
// `names` omitted → every Active user whose reported version is behind latest.
// Returns a per-user breakdown so the UI can show exactly who was skipped and why.
function sendUpdateReminderEmails(names, kind, overrideSubject, overrideBody) {
  requireAdmin_();
  kind = (kind === 'update') ? 'update' : 'reminder';

  var targets = [];
  if (Array.isArray(names) && names.length > 0) {
    names.forEach(function(n) {
      var u = lookupUserForEmail_(n);
      if (u) targets.push(u);
      else targets.push({ name: String(n), email: '', _missing: true });
    });
  } else {
    targets = getOutdatedActiveUsers_();
  }

  if (targets.length === 0) {
    return { success: true, sent: 0, skipped: 0, results: [], message: 'Every active user is already on the latest version.' };
  }

  var results = [], sent = 0, skipped = 0;
  targets.forEach(function(u) {
    if (u._missing) {
      skipped++; results.push({ name: u.name, sent: false, error: 'not found in roster' }); return;
    }
    if (u.status === USER_STATUS.REMOVED) {
      skipped++; results.push({ name: u.name, sent: false, error: 'user is removed' }); return;
    }
    var r = sendUserEmail_(kind, u, overrideSubject, overrideBody);
    if (r.sent) sent++; else skipped++;
    results.push({ name: u.name, email: u.email, sent: r.sent, error: r.error || null });
  });

  log_('Mass ' + kind + ' email: ' + sent + ' sent, ' + skipped + ' skipped');
  return { success: true, sent: sent, skipped: skipped, results: results };
}

// Active users whose reported version is behind getLatestVersion().
// Users that have never reported a version are excluded — there is nothing to
// compare, and they are already surfaced by the never-seen/onboarding strip.
function getOutdatedActiveUsers_() {
  var latest = getLatestVersion();
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var out = [];
  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    if (normalizeUserStatus_(data[i][REG_COL_STATUS]) === USER_STATUS.REMOVED) continue;
    var version = data[i][6] ? String(data[i][6]).trim() : '';
    if (!version) continue;
    if (compareVersions_(version, latest) >= 0) continue;
    out.push({
      name:    name,
      email:   data[i][REG_COL_EMAIL]  ? String(data[i][REG_COL_EMAIL]).trim()  : '',
      system:  data[i][REG_COL_SYSTEM] ? String(data[i][REG_COL_SYSTEM]).trim() : '',
      version: version,
      status:  normalizeUserStatus_(data[i][REG_COL_STATUS])
    });
  }
  return out;
}

// Server-side semver compare (the client has its own copy in JavaScript.html).
// Returns <0 if a is older, 0 if equal, >0 if a is newer.
function compareVersions_(a, b) {
  var pa = String(a || '0').split(/[.\-+]/);
  var pb = String(b || '0').split(/[.\-+]/);
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var na = parseInt(pa[i], 10); if (!isFinite(na)) na = 0;
    var nb = parseInt(pb[i], 10); if (!isFinite(nb)) nb = 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

// Read-only preview for the Compliance page: who would receive a mass reminder,
// and who cannot be reached because they have no email on file.
function getUpdateReminderPreview() {
  requireAdmin_();
  var outdated = getOutdatedActiveUsers_();
  var reachable = outdated.filter(function(u) { return u.email && isValidEmail_(u.email); });
  var unreachable = outdated.filter(function(u) { return !u.email || !isValidEmail_(u.email); });
  var urls = getUtilityDownloadConfig().urls;
  return {
    latestVersion: getLatestVersion(),
    outdatedCount: outdated.length,
    reachable: reachable,
    unreachable: unreachable,
    downloadConfigured: !!(urls.windows || urls.macos || urls.linux)
  };
}

// -------------------- WEEKLY ADMIN DIGESTS --------------------
// Requirement 5: every Monday 12:00 PM IST, mail Dhairya + Tejas two reports —
// users whose weekly report never landed, and users still on an old version.
// Recipients default to the admin allowlist so the digest is never silently
// sent nowhere.

function getWeeklyDigestRecipients_() {
  var list = [];
  try {
    var raw = PropertiesService.getScriptProperties().getProperty('weekly_digest_recipients') || '';
    raw.split(/[,\s;]+/).forEach(function(em) {
      em = em.trim().toLowerCase();
      if (em && isValidEmail_(em) && list.indexOf(em) === -1) list.push(em);
    });
  } catch (e) {}
  if (list.length === 0) list = getAdminAllowlist_();
  return list;
}

function getWeeklyDigestConfig() {
  requireAdmin_();
  var raw = '';
  try { raw = PropertiesService.getScriptProperties().getProperty('weekly_digest_recipients') || ''; } catch (e) {}
  return {
    recipients: getWeeklyDigestRecipients_(),
    explicitlyConfigured: !!raw,
    usingAdminAllowlistFallback: !raw,
    triggerInstalled: isWeeklyDigestTriggerInstalled(),
    scheduleDescription: 'Mondays at 12:00 ' + (Session.getScriptTimeZone() || 'Asia/Kolkata')
  };
}

function setWeeklyDigestRecipients(emailsCsv) {
  requireAdmin_();
  var clean = String(emailsCsv || '').split(/[,\s;]+/)
    .map(function(e) { return e.trim().toLowerCase(); })
    .filter(Boolean);
  var bad = clean.filter(function(e) { return !isValidEmail_(e); });
  if (bad.length > 0) return { success: false, error: 'Invalid address(es): ' + bad.join(', ') };
  PropertiesService.getScriptProperties().setProperty('weekly_digest_recipients', clean.join(','));
  log_('Weekly digest recipients set to: ' + clean.join(', '));
  return { success: true, recipients: getWeeklyDigestRecipients_() };
}

// The Monday-to-Sunday window that just closed. Called on Monday, this returns
// the *previous* week — the period the reports were supposed to cover.
function lastCompletedWeekWindow_() {
  var tz = Session.getScriptTimeZone() || 'Asia/Kolkata';
  var thisMonday = getCurrentWeekStart_();               // yyyy-MM-dd, script tz
  var parts = thisMonday.split('-');
  var anchor = new Date(Date.UTC(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, parseInt(parts[2], 10), 12, 0, 0));
  anchor.setUTCDate(anchor.getUTCDate() - 7);
  var start = Utilities.formatDate(anchor, tz, 'yyyy-MM-dd');
  anchor.setUTCDate(anchor.getUTCDate() + 6);
  var end = Utilities.formatDate(anchor, tz, 'yyyy-MM-dd');
  return { weekStart: start, weekEnd: end, label: formatWeekLabel_(start, end) };
}

// The Monday-to-Sunday window IN PROGRESS right now.
//
// Bug found 2026-07-30: without this, the only dated folder that exists during
// an in-progress week is the PREVIOUS (closed) one, still being refreshed for
// late arrivals. Every ordinary upload during the current week — not just
// genuine stragglers — was newer than what that old folder held, so the daily
// archive job kept sweeping today's activity into last week's folder simply
// because there was nowhere else for it to go. "July 20-26 2026" is supposed to
// mean reports observed for that period, not "whatever's newest as of today."
// Creating and maintaining the CURRENT week's folder from day one gives new
// activity somewhere correct to land, closing that gap.
function currentWeekWindow_() {
  var tz = Session.getScriptTimeZone() || 'Asia/Kolkata';
  var start = getCurrentWeekStart_();                    // yyyy-MM-dd, script tz
  var parts = start.split('-');
  var anchor = new Date(Date.UTC(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, parseInt(parts[2], 10), 12, 0, 0));
  anchor.setUTCDate(anchor.getUTCDate() + 6);
  var end = Utilities.formatDate(anchor, tz, 'yyyy-MM-dd');
  return { weekStart: start, weekEnd: end, label: formatWeekLabel_(start, end) };
}

// "July 20-26 2026" — the folder-naming convention from the requirements,
// reused here so the digest and the (phase 2) report folders read identically.
function formatWeekLabel_(startIso, endIso) {
  var tz = Session.getScriptTimeZone() || 'Asia/Kolkata';
  function d(iso) {
    var p = iso.split('-');
    return new Date(Date.UTC(parseInt(p[0], 10), parseInt(p[1], 10) - 1, parseInt(p[2], 10), 12, 0, 0));
  }
  var s = d(startIso), e = d(endIso);
  var sMonth = Utilities.formatDate(s, tz, 'MMMM');
  var eMonth = Utilities.formatDate(e, tz, 'MMMM');
  var sDay   = Utilities.formatDate(s, tz, 'd');
  var eDay   = Utilities.formatDate(e, tz, 'd');
  var year   = Utilities.formatDate(e, tz, 'yyyy');
  return (sMonth === eMonth)
    ? sMonth + ' ' + sDay + '-' + eDay + ' ' + year
    : sMonth + ' ' + sDay + '-' + eMonth + ' ' + eDay + ' ' + year;
}

// Active users with no SUCCESS logged for the given week-start.
function getMissingReportUsers_(weekStart) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();

  var roster = [];
  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    if (normalizeUserStatus_(data[i][REG_COL_STATUS]) === USER_STATUS.REMOVED) continue;
    roster.push({
      name:       name,
      email:      data[i][REG_COL_EMAIL]  ? String(data[i][REG_COL_EMAIL]).trim()  : '',
      system:     data[i][REG_COL_SYSTEM] ? String(data[i][REG_COL_SYSTEM]).trim() : '',
      lastUpload: data[i][5] ? String(data[i][5]) : ''
    });
  }

  // Paused users are intentionally not reporting — excluding them keeps the
  // digest actionable rather than a standing list of known-quiet machines.
  var pausedSet = getPausedDevelopersMap_();

  var reported = {};
  var logSheet = ss.getSheetByName('ComplianceLog');
  if (logSheet) {
    var rows = getRecentLogRows_(logSheet, 8000);
    for (var r = 0; r < rows.length; r++) {
      if (!rows[r][0]) continue;
      var ws = rows[r][2];
      if (ws && typeof ws.getTime === 'function') {
        ws = Utilities.formatDate(ws, Session.getScriptTimeZone(), 'yyyy-MM-dd');
      } else {
        ws = String(ws || '').trim();
      }
      if (ws !== weekStart) continue;
      if (String(rows[r][3] || '').trim().toUpperCase() !== 'SUCCESS') continue;
      reported[String(rows[r][1] || '').trim().toLowerCase()] = true;
    }
  }

  return roster.filter(function(u) {
    if (pausedSet[u.name.toLowerCase()]) return false;
    return !reported[u.name.toLowerCase()];
  });
}

// The Monday 12:00 digest. Public (no requireAdmin_) so the time-driven
// trigger can run it with no active user session.
function runWeeklyAdminDigest() {
  var win = lastCompletedWeekWindow_();
  var missing  = getMissingReportUsers_(win.weekStart);
  var outdated = getOutdatedActiveUsers_();
  var latest   = getLatestVersion();
  var recipients = getWeeklyDigestRecipients_();

  if (recipients.length === 0) {
    log_('WeeklyDigest: no recipients configured (weekly_digest_recipients and admin_emails are both empty) — skipping');
    return { success: false, error: 'No recipients configured', missing: missing.length, outdated: outdated.length };
  }

  var lines = [];
  lines.push('Claude Usage Uploader — weekly compliance digest');
  lines.push('Reporting period: ' + win.label + '  (' + win.weekStart + ' 00:00 to ' + win.weekEnd + ' 23:59 ' + (Session.getScriptTimeZone() || 'Asia/Kolkata') + ')');
  lines.push('');
  lines.push('--------------------------------------------------');
  lines.push('1. MISSING REPORTS (' + missing.length + ')');
  lines.push('--------------------------------------------------');
  if (missing.length === 0) {
    lines.push('  All active users uploaded a report for this period.');
  } else {
    lines.push('  These active users have no successful upload for the period:');
    lines.push('');
    missing.forEach(function(u) {
      var last = u.lastUpload ? ('last upload ' + String(u.lastUpload).substring(0, 10)) : 'never uploaded';
      lines.push('  • ' + u.name + ' — ' + last + (u.email ? '  <' + u.email + '>' : '  (no email on file)'));
    });
  }
  lines.push('');
  lines.push('--------------------------------------------------');
  lines.push('2. OUTDATED UTILITY VERSIONS (' + outdated.length + ')');
  lines.push('--------------------------------------------------');
  lines.push('  Current release: v' + latest);
  lines.push('');
  if (outdated.length === 0) {
    lines.push('  Every active user is on the latest version.');
  } else {
    outdated.forEach(function(u) {
      lines.push('  • ' + u.name + ' — running v' + u.version +
                 (u.email ? '  <' + u.email + '>' : '  (no email on file)'));
    });
    lines.push('');
    lines.push('  Use the Users page → "Email update reminder" to notify them, or the');
    lines.push('  Version Matrix page to push a silent hot-patch.');
  }
  lines.push('');
  lines.push('--------------------------------------------------');
  lines.push('Generated ' + Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'Asia/Kolkata', 'yyyy-MM-dd HH:mm z'));

  var subject = '[Claude Usage] Weekly digest ' + win.label +
                ' — ' + missing.length + ' missing, ' + outdated.length + ' outdated';
  try {
    GmailApp.sendEmail(recipients.join(','), subject, lines.join('\n'));
    log_('WeeklyDigest: sent to ' + recipients.join(', ') +
         ' (' + missing.length + ' missing, ' + outdated.length + ' outdated)');
  } catch (e) {
    log_('WeeklyDigest: send failed: ' + e.toString());
    return { success: false, error: e.toString() };
  }

  return {
    success: true,
    period: win,
    recipients: recipients,
    missingCount: missing.length,
    outdatedCount: outdated.length,
    missing: missing,
    outdated: outdated
  };
}

// Admin-gated entry point for the dashboard's "Send now" button.
// runWeeklyAdminDigest itself stays ungated so the time-driven trigger can call
// it with no active user session — but this web app is deployed with
// ANYONE_ANONYMOUS access, so the client must not reach the ungated version
// directly or any visitor could fire the digest at will.
function adminSendWeeklyDigestNow() {
  requireAdmin_();
  return runWeeklyAdminDigest();
}

// Preview the digest from the dashboard without emailing anyone.
function previewWeeklyAdminDigest() {
  requireAdmin_();
  var win = lastCompletedWeekWindow_();
  return {
    period: win,
    recipients: getWeeklyDigestRecipients_(),
    latestVersion: getLatestVersion(),
    missing: getMissingReportUsers_(win.weekStart),
    outdated: getOutdatedActiveUsers_()
  };
}

function isWeeklyDigestTriggerInstalled() {
  var triggers = ScriptApp.getProjectTriggers();
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'runWeeklyAdminDigest') return true;
  }
  return false;
}

// Idempotent installer used by the one-time init. Script timezone is
// Asia/Kolkata (see appsscript.json), so atHour(12) is 12:00 PM IST.
function ensureWeeklyDigestTrigger_() {
  if (isWeeklyDigestTriggerInstalled()) return false;
  ScriptApp.newTrigger('runWeeklyAdminDigest')
    .timeBased()
    .onWeekDay(ScriptApp.WeekDay.MONDAY)
    .atHour(12)
    .create();
  log_('WeeklyDigest: trigger installed (Mondays 12:00 ' + (Session.getScriptTimeZone() || 'Asia/Kolkata') + ')');
  return true;
}

function installWeeklyDigestTrigger() {
  requireAdmin_();
  var created = ensureWeeklyDigestTrigger_();
  return { success: true, created: created, message: created ? 'Weekly digest trigger installed' : 'Already installed' };
}

function uninstallWeeklyDigestTrigger() {
  requireAdmin_();
  var triggers = ScriptApp.getProjectTriggers();
  var removed = 0;
  for (var i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'runWeeklyAdminDigest') {
      ScriptApp.deleteTrigger(triggers[i]);
      removed++;
    }
  }
  return { success: true, removed: removed };
}

// ================================================================
// v5.1 — ONE-TIME SETUP HELPER
// ================================================================
// Everything the v5 features need that cannot be inferred from the sheets lives
// in Script Properties. Rather than making you click through Project Settings
// and type key/value pairs by hand, edit the four constants below and run this
// function once from the editor (Run ▸ setupUtilityDistribution).
//
// Re-running it is safe: it overwrites the same keys with the same values.
//
// NOTE ON THE TWO VERSION SOURCES — they are independent and must agree:
//   • The AGENT self-updates by reading the GitHub Gist manifest
//     (gist.githubusercontent.com/.../version.json). Only editing the Gist
//     changes what the fleet installs. This function cannot touch it — Apps
//     Script has no external-request scope here, by deliberate design.
//   • THIS DASHBOARD decides who is "outdated" from LATEST_VERSION below.
// Ship a new binary => update the Gist AND re-run this with the new version,
// or the Version Matrix and the reminder emails will report the wrong thing.

// --- EDIT THESE FOUR, THEN RUN ---------------------------------------------

// Must match `latestVersion` in the Gist manifest.
//
// ⚠ ORDER MATTERS. These are already set to 2.0.6, but the v2.0.6 release does not
// exist until you have tagged + pushed and CI has published it. Do NOT run
// setupUtilityDistribution until the Gist says 2.0.6, or the dashboard will flag
// the whole fleet as outdated and the mass-reminder will email 76 people a
// download link that 404s. Run it as the LAST step of the release.
var SETUP_LATEST_VERSION = '2.0.9';

// FIRST-INSTALL download links. Must be https://.
//
// These are deliberately NOT the GitHub release URLs. The bare executable cannot
// run on its own: it resolves service-account-key.json from its own directory
// (GOOGLE_KEY_FILE in claude-usage-uploader.js), and that key is a live credential
// that must never be attached to a public release. A new user who downloads the
// raw .exe gets "AUTH_KEY_MISSING" every time.
//
// So first installs point at an internal, domain-restricted Drive ZIP containing
// the executable, the key, and the installer together. Auto-update keeps using the
// public GitHub URLs in the Gist manifest, which is correct — an already-installed
// agent has the key sitting beside it, so it only needs the replacement binary.
//
// macOS and Linux are intentionally EMPTY: no equivalent bundle exists yet. An
// empty URL makes sendUserEmail_ refuse to send, which is the right outcome —
// far better than mailing a Mac user a Windows executable. Build the matching
// bundles and fill these in if non-Windows machines ever join the fleet.
// ⚠ SHARING MUST BE RESTRICTED. This ZIP contains service-account-key.json, a
// live credential. On 2026-07-28 both the v2.0.6 and v2.0.7 bundles were found
// set to "Anyone with the link" — the full archive, key included, downloaded
// with no Google account at all. Whenever you replace this file, re-check
// Share on the Drive file itself: uploading a new version does NOT inherit the
// previous file's (or the parent folder's) restriction.
var SETUP_DOWNLOAD_URLS = {
  windows: 'https://drive.google.com/file/d/1pzTuzaJ8ptJNDzgxpUjDbGx-mE_jGkZM/view?usp=sharing',
  macos:   '',
  linux:   ''
};

// Who receives the Monday 12:00 IST digest. Set to tpansuriya@sigmasolve.com
// only for now (2026-07-30) — add the rest of the requirement's recipients
// (Dhairya) once confirmed; this is a deliberate interim scope, not the final
// list.
var SETUP_DIGEST_RECIPIENTS = 'tpansuriya@sigmasolve.com';

// Who may use the admin actions. Leave '' to stay in pilot mode (any visitor
// with the link can act — fine for a pilot, not for production).
var SETUP_ADMIN_EMAILS = '';

// --------------------------------------------------------------------------

function setupUtilityDistribution() {
  var report = { applied: [], skipped: [], warnings: [] };
  var props = PropertiesService.getScriptProperties();

  // 1. Latest version (drives the dashboard's outdated/drift detection)
  props.setProperty('latest_uploader_version', String(SETUP_LATEST_VERSION).trim());
  report.applied.push('latest_uploader_version = ' + SETUP_LATEST_VERSION);

  // 2. Download URLs — setUtilityDownloadConfig validates the https:// scheme
  var urlResult = setUtilityDownloadConfig(SETUP_DOWNLOAD_URLS);
  Object.keys(SETUP_DOWNLOAD_URLS).forEach(function(p) {
    report.applied.push('download_url_' + p + ' = ' + SETUP_DOWNLOAD_URLS[p]);
  });

  // 3. Digest recipients — refuse the shipped placeholders outright
  if (/REPLACE_/i.test(SETUP_DIGEST_RECIPIENTS)) {
    report.skipped.push('weekly_digest_recipients — still contains the REPLACE_ placeholders');
    report.warnings.push('Digest recipients NOT set. Edit SETUP_DIGEST_RECIPIENTS with the real ' +
                         'addresses and re-run, or set them on the Health page. Until then the ' +
                         'Monday digest falls back to admin_emails, and is skipped if that is empty too.');
  } else {
    var r = setWeeklyDigestRecipients(SETUP_DIGEST_RECIPIENTS);
    if (r.success) report.applied.push('weekly_digest_recipients = ' + r.recipients.join(', '));
    else report.warnings.push('Digest recipients rejected: ' + r.error);
  }

  // 4. Admin allowlist (optional — empty keeps pilot mode)
  if (String(SETUP_ADMIN_EMAILS).trim()) {
    var a = setAdminAllowlist(SETUP_ADMIN_EMAILS);
    report.applied.push('admin_emails = ' + a.allowlist.join(', '));
  } else {
    report.skipped.push('admin_emails — left empty, dashboard stays in pilot mode (no access gate)');
    report.warnings.push('PILOT MODE: anyone with the web-app link can add/remove users and send ' +
                         'mail. Set SETUP_ADMIN_EMAILS before treating this as production.');
  }

  // 5. Make sure the scheduled jobs actually exist
  try {
    var digestCreated = ensureWeeklyDigestTrigger_();
    report.applied.push('weekly digest trigger: ' + (digestCreated ? 'installed' : 'already present'));
  } catch (e) {
    report.warnings.push('Could not install the weekly digest trigger: ' + e.toString());
  }
  try {
    installPruneTrigger();
    report.applied.push('daily prune + retention-purge trigger: ensured');
  } catch (e) {
    report.warnings.push('Could not install the daily prune trigger: ' + e.toString());
  }
  try {
    var archiveCreated = ensureWeeklyArchiveTrigger_();
    report.applied.push('daily weekly-report archive trigger: ' + (archiveCreated ? 'installed' : 'already present'));
    // Prove Drive access now rather than discovering it silently failed later.
    var access = checkWeeklyArchiveAccess();
    report.archiveAccess = access;
    if (!access.canWrite) {
      report.warnings.push('ARCHIVE NOT WRITABLE: ' + (access.verdict || access.error) +
                           ' Weekly report folders cannot be created until this is fixed. ' +
                           (access.fix || ''));
    }
  } catch (e) {
    report.warnings.push('Could not set up the weekly report archive: ' + e.toString());
  }

  // 6. Prove the email path resolves end to end before anyone relies on it
  var probe = downloadUrlForSystem_('Windows (Company)');
  report.emailPathReady = !!probe;
  if (!probe) report.warnings.push('Download URL for Windows did not resolve — setup emails will refuse to send.');

  report.currentConfig = getUtilityDownloadConfig();
  report.reminder = 'The AGENT auto-updates from the GitHub Gist, which this function cannot edit. ' +
                    'Shipping a new binary means updating the Gist too, then re-running this with the new version.';

  log_('setupUtilityDistribution: ' + report.applied.length + ' setting(s) applied, ' +
       report.warnings.length + ' warning(s)');
  return report;
}

// Requirement 5: the weekly report period runs Monday 00:00 IST → Sunday 23:59
// IST, so the fleet's generation schedule is pinned to Monday 00:00. Applied
// once, on the v5 init, and logged — an admin can still change it afterwards
// from the Settings card and this will not overwrite them again.
function applyWeeklyGenerationDefault_() {
  var props = PropertiesService.getScriptProperties();
  if (props.getProperty('weeklyScheduleAligned') === '1') return false;
  var sheet = ensureSettingsSheet_();
  setSettingValue_(sheet, 'uploadFrequency', 'weekly');
  setSettingValue_(sheet, 'globalUploadDay', 'Monday');
  setTimeSettingValue_(sheet, 'globalUploadTime', '00:00');
  props.setProperty('weeklyScheduleAligned', '1');
  invalidateCache_();
  log_('v5 init: fleet generation schedule pinned to weekly / Monday / 00:00 ' +
       (Session.getScriptTimeZone() || 'Asia/Kolkata'));
  return true;
}

// ================================================================
// v5.1 — LOGGING WRAPPERS
// ================================================================
// The Apps Script editor never prints a function's return value, so running
// diagnoseFleetPresence() or setupUtilityDistribution() directly shows only
// "Execution completed" with an empty log. Run these instead — they serialise
// the result into the execution log where you can actually read it.

function logFleetDiagnosis() {
  Logger.log(JSON.stringify(diagnoseFleetPresence(), null, 2));
}

function logWebhookAuthDiagnosis() {
  Logger.log(JSON.stringify(diagnoseWebhookAuth(), null, 2));
}

// Pass a name to inspect one person, or omit for the whole fleet summary.
//   logDriveTruth()                → fleet summary + the mismatched users
//   logDriveTruth('Umang_Patel')   → just that user
function logDriveTruth(name) {
  Logger.log(JSON.stringify(diagnoseDriveVsRoster(name), null, 2));
}

// v5.1: GROUND TRUTH — compares what is actually sitting in the shared Drive
// folder against what the roster believes.
//
// Why this exists: report files reach Drive through the service account, which
// never touches the GAS webhook. Heartbeats and the SUCCESS ping DO go through
// the webhook. So while signature verification is failing, a developer can be
// uploading perfectly while the dashboard reports them Offline and
// non-compliant. Drive file mtimes are the only trustworthy record in that
// situation — this reads them directly.
function diagnoseDriveVsRoster(onlyName) {
  var filter = String(onlyName || '').trim().toLowerCase();

  // 1. Index the real files by developer prefix.
  var driveFiles = {};
  var scanned = 0, skipped = 0;
  try {
    var folder = DriveApp.getFolderById(SHARED_DRIVE_FOLDER_ID);
    var files = folder.getFiles();
    while (files.hasNext()) {
      var f = files.next();
      if (f.isTrashed()) continue;
      var fn = f.getName();
      var isDaily   = /_claude_daily\.json$/i.test(fn);
      var isSession = /_claude_session\.json$/i.test(fn);
      if (!isDaily && !isSession) { skipped++; continue; }
      scanned++;
      var prefix = fn.replace(/_claude_(daily|session)\.json$/i, '');
      var key = prefix.toLowerCase();
      if (!driveFiles[key]) driveFiles[key] = { prefix: prefix, daily: null, session: null };
      var stamp = f.getLastUpdated();
      if (isDaily) driveFiles[key].daily = stamp;
      else         driveFiles[key].session = stamp;
    }
  } catch (e) {
    return { error: 'Could not read the shared Drive folder: ' + e.toString(),
             hint: 'The executing account needs at least Content Manager on the shared drive.' };
  }

  // 2. Walk the roster and compare.
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var rows = [];
  var summary = {
    rosterUsers: 0, driveFilePairsFound: Object.keys(driveFiles).length,
    driveNewerThanRoster: 0, rosterMatchesDrive: 0, noDriveFileAtAll: 0
  };

  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    if (normalizeUserStatus_(data[i][REG_COL_STATUS]) === USER_STATUS.REMOVED) continue;
    if (filter && name.toLowerCase().indexOf(filter) === -1) continue;
    summary.rosterUsers++;

    // Uploader writes <Name_with_underscores>_claude_*.json
    var key = name.replace(/\s+/g, '_').toLowerCase();
    var df = driveFiles[key] || null;

    function ms(v) {
      if (!v) return 0;
      if (typeof v.getTime === 'function') return v.getTime();
      var t = new Date(String(v)).getTime();
      return isFinite(t) ? t : 0;
    }
    var rosterUploadMs = ms(data[i][5]); // LastUpload, written only by the webhook
    var driveNewestMs = df ? Math.max(ms(df.daily), ms(df.session)) : 0;

    var state;
    if (!df) {
      state = 'NO_DRIVE_FILE';
      summary.noDriveFileAtAll++;
    } else if (driveNewestMs > rosterUploadMs + 60000) {
      // Drive is materially ahead of what the roster recorded → the upload
      // worked but its SUCCESS ping never got accepted.
      state = 'DRIVE_NEWER_THAN_ROSTER';
      summary.driveNewerThanRoster++;
    } else {
      state = 'IN_SYNC';
      summary.rosterMatchesDrive++;
    }

    if (filter || state !== 'IN_SYNC') {
      rows.push({
        name: name,
        state: state,
        driveDailyModified:   df && df.daily   ? df.daily.toISOString()   : null,
        driveSessionModified: df && df.session ? df.session.toISOString() : null,
        driveNewestAgeHours:  driveNewestMs ? Math.round((Date.now() - driveNewestMs) / 3600000) : null,
        rosterLastUpload:     rosterUploadMs ? new Date(rosterUploadMs).toISOString() : null,
        rosterLastUploadAgeHours: rosterUploadMs ? Math.round((Date.now() - rosterUploadMs) / 3600000) : null,
        hoursRosterIsBehind: (driveNewestMs && rosterUploadMs)
          ? Math.round((driveNewestMs - rosterUploadMs) / 3600000) : null
      });
    }
  }

  rows.sort(function(a, b) { return (b.hoursRosterIsBehind || 0) - (a.hoursRosterIsBehind || 0); });

  var verdict;
  if (summary.driveNewerThanRoster > 0) {
    verdict = summary.driveNewerThanRoster + ' user(s) have FRESHER files in Drive than the roster knows about. ' +
      'Their uploads are working; only the status ping is being lost. Treat these people as COMPLIANT — ' +
      'the dashboard is under-reporting them because of the webhook signature failure, not because they did nothing.';
  } else if (summary.noDriveFileAtAll === summary.rosterUsers && summary.rosterUsers > 0) {
    verdict = 'No Drive files found for any user checked. Either the folder ID is wrong or nothing has ever uploaded.';
  } else {
    verdict = 'Roster and Drive agree for everyone checked — no hidden uploads. Missing reports are genuinely missing.';
  }

  return {
    verdict: verdict,
    scope: filter ? ('filtered to names containing "' + onlyName + '"') : 'entire active roster',
    summary: summary,
    driveScan: { reportFilesSeen: scanned, otherFilesIgnored: skipped, folderId: SHARED_DRIVE_FOLDER_ID },
    users: rows.slice(0, 100),
    note: 'rosterLastUpload comes from the SUCCESS webhook ping; drive*Modified comes from the file itself. ' +
          'A gap between them isolates a reporting-channel fault from a genuine non-upload.'
  };
}

// v5.1: pinpoint WHY doPost is answering sig_mismatch.
//
// The check has three independent inputs — the secret, the signed message
// (ts + '.' + body), and the freshness/replay window. This exercises the exact
// verifier the fleet hits, using a signature built the same way the Node client
// builds it, so a pass proves the SERVER side is sound and the fault is on the
// client or in transit. Reveals no secret values, only lengths and fingerprints.
function diagnoseWebhookAuth() {
  var out = { checks: [], secretState: {}, rejectionHistory: {} };

  // --- 1. Which secrets will the verifier accept? ---
  var secrets = getWebhookSecrets_();
  var override = '';
  try { override = PropertiesService.getScriptProperties().getProperty('hmac_secret') || ''; } catch (e) {}
  out.secretState = {
    acceptedSecretCount: secrets.length,
    overrideConfigured: !!override,
    overrideLength: override ? override.length : 0,
    // Fingerprint, not the secret — enough to compare against the client build.
    compiledDefaultFingerprint: computeHmac256_(WEBHOOK_HMAC_SECRET_DEFAULT, 'fingerprint').substring(0, 12),
    compiledDefaultLength: WEBHOOK_HMAC_SECRET_DEFAULT.length,
    retiredSecretsStillAccepted: getRetiredSecretCount_(),
    retiredSecretWarning: getRetiredSecretCount_() > 0
      ? 'A retired (publicly known) secret is still accepted so pre-v2.0.6 agents keep ' +
        'reporting. Anyone can forge pings until it is removed. Empty ' +
        'WEBHOOK_HMAC_SECRET_RETIRED once the Version Matrix shows nobody below v2.0.6.'
      : null,
    note: 'The compiled default is always accepted, so an override can never lock out existing binaries.'
  };

  // --- 2. Round-trip the verifier with a correctly-signed request ---
  // Mirrors the client exactly: sig = HMAC_SHA256(secret, ts + '.' + rawBody).
  var body = JSON.stringify({ name: 'DIAG_SELFTEST', status: 'HEARTBEAT', message: 'auth self-test' });
  var ts = Math.floor(Date.now() / 1000).toString();
  var goodSig = computeHmac256_(WEBHOOK_HMAC_SECRET_DEFAULT, ts + '.' + body);
  var verdictGood = verifyWebhookSignature_({
    postData: { contents: body },
    parameter: { _ts: ts, _sig: goodSig }
  });
  out.checks.push({
    check: 'correctly-signed request accepted',
    pass: verdictGood === '',
    detail: verdictGood || 'accepted'
  });

  // --- 3. Confirm a wrong signature is actually rejected (verifier not inert) ---
  var badVerdict = verifyWebhookSignature_({
    postData: { contents: body },
    parameter: { _ts: Math.floor(Date.now() / 1000).toString(), _sig: 'deadbeef'.repeat(8) }
  });
  out.checks.push({
    check: 'tampered signature rejected',
    pass: badVerdict === 'sig_mismatch',
    detail: badVerdict
  });

  // --- 4. Freshness window the client must hit ---
  out.timing = {
    staleAfterSeconds: HMAC_STALE_SECS,
    futureToleranceSeconds: HMAC_FUTURE_TOL,
    serverUnixTime: Math.floor(Date.now() / 1000),
    serverTimeIso: new Date().toISOString(),
    note: 'A client clock off by more than these bounds is rejected as stale_ts/future_ts, NOT sig_mismatch.'
  };

  // --- 5. Is the rejection ongoing, or did it stop? ---
  // Logging is throttled to one row per developer per 10 min, so treat these as
  // a floor on the true rate, never an exact count.
  var reasons = {};
  var ages = { under15min: 0, under1h: 0, under6h: 0, under24h: 0, older: 0 };
  var newestMs = 0;
  var names = {};
  try {
    var appLog = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AppLog');
    if (appLog) {
      var rows = getRecentLogRows_(appLog, 1000);
      for (var i = 0; i < rows.length; i++) {
        var msg = String(rows[i][1] || '');
        if (msg.indexOf('doPost: signature rejected') !== 0) continue;
        var m = msg.match(/—\s*(\w+)/);
        var reason = m ? m[1] : 'unknown';
        reasons[reason] = (reasons[reason] || 0) + 1;
        var nm = msg.match(/for "([^"]+)"/);
        if (nm) names[nm[1]] = true;
        var ts2 = rows[i][0];
        var tms = (ts2 && typeof ts2.getTime === 'function') ? ts2.getTime() : new Date(String(ts2)).getTime();
        if (!isFinite(tms)) continue;
        if (tms > newestMs) newestMs = tms;
        var mins = (Date.now() - tms) / 60000;
        if (mins < 15)        ages.under15min++;
        else if (mins < 60)   ages.under1h++;
        else if (mins < 360)  ages.under6h++;
        else if (mins < 1440) ages.under24h++;
        else                  ages.older++;
      }
    }
  } catch (e) {}
  out.rejectionHistory = {
    byReason: reasons,
    byAge: ages,
    distinctDevelopersAffected: Object.keys(names).length,
    minutesSinceNewestRejection: newestMs ? Math.round((Date.now() - newestMs) / 60000) : null,
    caveat: 'Rejection logging is throttled per developer per 10 min — counts are a floor, not exact.'
  };

  // --- 6. Deployment identity ---
  // The binary posts to a hard-coded URL. If that deployment is pinned to an
  // older script version, the fleet is running code you are not editing.
  out.deployment = {
    scriptId: ScriptApp.getScriptId(),
    webAppUrlOfThisDeployment: ScriptApp.getService().getUrl(),
    urlCompiledIntoTheBinary: 'https://script.google.com/macros/s/AKfycby9bFBRwYLu1GF6urQn3saAuVacI95NjS2Jt2G3eiba3StKwu9i8POjXnlx224NMMXt/exec',
    note: 'These two must be the SAME deployment, or your agents are executing a different pinned version than the one you deploy to.'
  };

  var serverSideOk = out.checks.every(function(c) { return c.pass; });
  out.verdict = serverSideOk
    ? 'SERVER-SIDE HMAC IS CORRECT — a properly signed request is accepted and a bad one rejected. ' +
      'So sig_mismatch is coming from the client side or from something altering the request in transit ' +
      '(check urlCompiledIntoTheBinary vs webAppUrlOfThisDeployment first).'
    : 'SERVER-SIDE HMAC IS BROKEN — the verifier rejects even a correctly signed request. See checks[].';
  return out;
}

function logSetupResult() {
  Logger.log(JSON.stringify(setupUtilityDistribution(), null, 2));
}

function logRosterDuplicates() {
  Logger.log(JSON.stringify(diagnoseRosterDuplicates(), null, 2));
}

function logLegacySecretReadiness() {
  Logger.log(JSON.stringify(checkLegacySecretReadiness(), null, 2));
}

// v5.1: is it safe yet to empty WEBHOOK_HMAC_SECRET_RETIRED?
//
// Removing the retired secret closes a real hole (the old value is public and
// forgeable) but instantly locks out any agent still signing with it. "Nobody
// below v2.0.6" is the rule, with one refinement that matters: an agent that has
// been silent for a week cannot be locked out of anything it is not doing, and it
// will need the repair kit to come back regardless — and that kit installs
// v2.0.6. So only agents that are BOTH outdated AND still reporting can actually
// be harmed. This separates the two so the decision is evidence-based.
var LEGACY_CUTOFF_VERSION = '2.0.6';
var LEGACY_RECENT_DAYS = 7;

function checkLegacySecretReadiness() {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var now = Date.now();
  var recentMs = LEGACY_RECENT_DAYS * 86400000;

  var blocking = [];      // outdated AND recently reporting — would break
  var lowRisk = [];       // outdated but long silent — needs the kit anyway
  var unknownVersion = []; // never reported a version
  var upToDate = 0;

  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    if (normalizeUserStatus_(data[i][REG_COL_STATUS]) === USER_STATUS.REMOVED) continue;

    var version = data[i][6] ? String(data[i][6]).trim() : '';
    function ms(v) {
      if (!v) return 0;
      if (typeof v.getTime === 'function') return v.getTime();
      var t = new Date(String(v)).getTime();
      return isFinite(t) ? t : 0;
    }
    var lastAlive = Math.max(ms(data[i][3]), ms(data[i][4])); // heartbeat / pong
    var ageDays = lastAlive ? Math.round((now - lastAlive) / 86400000) : null;

    if (!version) {
      // No version on file. If it is also silent it is simply not in play.
      if (lastAlive && (now - lastAlive) < recentMs) {
        unknownVersion.push({ name: name, lastAliveDaysAgo: ageDays });
      }
      continue;
    }
    if (compareVersions_(version, LEGACY_CUTOFF_VERSION) >= 0) { upToDate++; continue; }

    var entry = { name: name, version: version, lastAliveDaysAgo: ageDays };
    if (lastAlive && (now - lastAlive) < recentMs) blocking.push(entry);
    else lowRisk.push(entry);
  }

  blocking.sort(function(a, b) { return (a.lastAliveDaysAgo || 0) - (b.lastAliveDaysAgo || 0); });

  var safe = blocking.length === 0 && unknownVersion.length === 0;
  var verdict;
  if (safe) {
    verdict = 'SAFE TO REMOVE. No agent that has reported in the last ' + LEGACY_RECENT_DAYS +
      ' days is below v' + LEGACY_CUTOFF_VERSION + '. Empty WEBHOOK_HMAC_SECRET_RETIRED ' +
      '(Code.gs line 18) and redeploy.' +
      (lowRisk.length ? ' The ' + lowRisk.length + ' long-silent agent(s) listed under lowRisk will be ' +
        'rejected if they ever wake up — they need the repair kit anyway, which installs v2.0.6.' : '');
  } else {
    verdict = 'NOT YET. ' + blocking.length + ' agent(s) are actively reporting on a version below v' +
      LEGACY_CUTOFF_VERSION + (unknownVersion.length ? ', plus ' + unknownVersion.length +
      ' reporting with no version on file' : '') + '. Removing the retired secret now would ' +
      'silence them immediately. Wait for auto-update, or force-update them from the Version Matrix.';
  }

  return {
    verdict: verdict,
    safeToRemove: safe,
    cutoffVersion: LEGACY_CUTOFF_VERSION,
    recentlyActiveWindowDays: LEGACY_RECENT_DAYS,
    upToDateCount: upToDate,
    blocking: blocking,
    lowRisk: lowRisk,
    reportingWithNoVersion: unknownVersion,
    howToRemove: 'In Code.gs replace lines 18-20 with:  var WEBHOOK_HMAC_SECRET_RETIRED = [];  ' +
                 'then Ctrl+S and Deploy > Manage deployments > New version.'
  };
}

// v5.1: DUPLICATE ROSTER ROWS.
//
// upsertRosterActivity_ deliberately takes no ScriptLock (a lock there would
// starve getDashboardData), so two concurrent first-pings from the same machine
// can each append a row. Separately, its lookup key is only
// name.trim().toLowerCase() — so "Dhruv Patel" and "Dhruv_Patel" register as two
// different people even though they are one human with one pair of Drive files.
//
// Effects: the registered-user count is inflated, activity is split across rows
// so at least one always looks stale, and every duplicate counts again as a
// separate non-reporting person in the compliance grid.
//
// This collapses separators and case the way the Drive filenames do, so it sees
// the same identity the uploader does. READ-ONLY.
function rosterIdentityKey_(name) {
  return String(name || '').trim().toLowerCase().replace(/[\s_\-]+/g, '_');
}

function diagnoseRosterDuplicates() {
  var sheet = ensureRegisteredDevelopersSheet();
  var data = sheet.getDataRange().getValues();
  var groups = {};

  for (var i = 1; i < data.length; i++) {
    var name = String(data[i][0] || '').trim();
    if (!name) continue;
    var key = rosterIdentityKey_(name);
    if (!groups[key]) groups[key] = [];
    groups[key].push({
      rowNumber: i + 1,
      name: name,
      registeredAt: stringifyCell_(data[i][1]),
      lastSeen:     stringifyCell_(data[i][2]),
      lastUpload:   stringifyCell_(data[i][5]),
      version:      data[i][6] ? String(data[i][6]).trim() : '',
      email:        data[i][REG_COL_EMAIL]  ? String(data[i][REG_COL_EMAIL]).trim()  : '',
      system:       data[i][REG_COL_SYSTEM] ? String(data[i][REG_COL_SYSTEM]).trim() : '',
      status:       normalizeUserStatus_(data[i][REG_COL_STATUS])
    });
  }

  var duplicateGroups = [];
  var totalRows = 0, distinctPeople = 0, redundantRows = 0;
  Object.keys(groups).forEach(function(key) {
    var g = groups[key];
    totalRows += g.length;
    distinctPeople++;
    if (g.length > 1) {
      redundantRows += g.length - 1;
      // Distinct spellings are the useful signal — it tells you whether this is
      // a write race (identical names) or name-form drift (different spellings).
      var spellings = {};
      g.forEach(function(r) { spellings[r.name] = true; });
      duplicateGroups.push({
        identity: key,
        rowCount: g.length,
        distinctSpellings: Object.keys(spellings),
        likelyCause: Object.keys(spellings).length > 1
          ? 'name-form drift (different spellings of one person)'
          : 'concurrent write race (identical name appended twice)',
        rows: g
      });
    }
  });

  duplicateGroups.sort(function(a, b) { return b.rowCount - a.rowCount; });

  return {
    verdict: redundantRows === 0
      ? 'No duplicate roster rows. The registered count is trustworthy.'
      : redundantRows + ' redundant row(s) across ' + duplicateGroups.length + ' person(ple). ' +
        'True distinct people = ' + distinctPeople + ', not ' + totalRows + '. Run adminMergeRosterDuplicates() to fix.',
    totalRosterRows: totalRows,
    distinctPeople: distinctPeople,
    redundantRows: redundantRows,
    duplicateGroups: duplicateGroups
  };
}

function stringifyCell_(v) {
  if (!v) return '';
  if (typeof v.getTime === 'function') return v.toISOString();
  return String(v).trim();
}

// Collapses duplicate identities into one row, keeping the best value from each
// column, then deletes the redundant rows. Snapshots the sheet to a hidden tab
// first so the merge is reversible.
//
// DESTRUCTIVE — run diagnoseRosterDuplicates() first and read what it plans to
// touch. Pass dryRun=true to see the merge plan without writing anything.
function adminMergeRosterDuplicates(dryRun) {
  requireAdmin_();
  var report = { dryRun: !!dryRun, merged: [], rowsDeleted: 0, backupSheet: null };

  var lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    var sheet = ensureRegisteredDevelopersSheet();
    var data = sheet.getDataRange().getValues();

    var groups = {};
    for (var i = 1; i < data.length; i++) {
      var name = String(data[i][0] || '').trim();
      if (!name) continue;
      var key = rosterIdentityKey_(name);
      if (!groups[key]) groups[key] = [];
      groups[key].push({ rowNumber: i + 1, row: data[i] });
    }

    var dupKeys = Object.keys(groups).filter(function(k) { return groups[k].length > 1; });
    if (dupKeys.length === 0) {
      report.verdict = 'Nothing to merge — no duplicate identities found.';
      return report;
    }

    if (!dryRun) {
      try {
        var parent = sheet.getParent();
        var backupName = 'RegisteredDevelopers_predupe_' +
          Utilities.formatDate(new Date(), 'UTC', 'yyyyMMdd_HHmmss');
        sheet.copyTo(parent).setName(backupName).hideSheet();
        report.backupSheet = backupName;
      } catch (e) {
        // Refuse to run destructively without a snapshot.
        report.verdict = 'ABORTED — could not create the safety snapshot: ' + e.toString();
        return report;
      }
    }

    function ms(v) {
      if (!v) return 0;
      if (typeof v.getTime === 'function') return v.getTime();
      var t = new Date(String(v)).getTime();
      return isFinite(t) ? t : 0;
    }
    function newest(rows, idx) {
      var best = '', bestMs = 0;
      rows.forEach(function(r) {
        var m = ms(r.row[idx]);
        if (m > bestMs) { bestMs = m; best = stringifyCell_(r.row[idx]); }
      });
      return best;
    }
    function oldest(rows, idx) {
      var best = '', bestMs = Infinity;
      rows.forEach(function(r) {
        var m = ms(r.row[idx]);
        if (m > 0 && m < bestMs) { bestMs = m; best = stringifyCell_(r.row[idx]); }
      });
      return best;
    }
    function firstNonEmpty(rows, idx) {
      for (var k = 0; k < rows.length; k++) {
        var v = rows[k].row[idx];
        if (v !== null && v !== undefined && String(v).trim() !== '') return String(v).trim();
      }
      return '';
    }

    var deletions = [];
    dupKeys.forEach(function(key) {
      var g = groups[key];
      // Canonical name: prefer the underscore form the uploader actually sends,
      // since that is what the Drive filenames and incoming pings use.
      var canonical = g[0].row[0];
      for (var k = 0; k < g.length; k++) {
        if (String(g[k].row[0]).indexOf('_') !== -1) { canonical = g[k].row[0]; break; }
      }
      // Keep the row with the newest LastSeen — least likely to be the orphan.
      var keeper = g[0];
      g.forEach(function(r) { if (ms(r.row[2]) > ms(keeper.row[2])) keeper = r; });

      // A Removed/Paused marking on ANY duplicate must survive the merge —
      // silently reactivating a removed person would be the worst outcome here.
      var statuses = g.map(function(r) { return normalizeUserStatus_(r.row[REG_COL_STATUS]); });
      var mergedStatus = statuses.indexOf(USER_STATUS.REMOVED) !== -1 ? USER_STATUS.REMOVED
                       : statuses.indexOf(USER_STATUS.PAUSED)  !== -1 ? USER_STATUS.PAUSED
                       : USER_STATUS.ACTIVE;

      var mergedRow = [
        String(canonical).trim(),
        oldest(g, 1) || new Date().toISOString(), // RegisteredAt — earliest wins
        newest(g, 2),                             // LastSeen
        newest(g, 3),                             // LastHeartbeat
        newest(g, 4),                             // LastPong
        newest(g, 5),                             // LastUpload
        firstNonEmpty(g, 6),                      // Version
        newest(g, 7),                             // NextPollAt
        newest(g, 8),                             // LastUpdateCheck
        firstNonEmpty(g, REG_COL_EMAIL),
        firstNonEmpty(g, REG_COL_SYSTEM),
        mergedStatus,
        newest(g, REG_COL_REMOVED)
      ];

      report.merged.push({
        identity: key,
        canonicalName: mergedRow[0],
        collapsedFrom: g.map(function(r) { return { row: r.rowNumber, name: String(r.row[0]).trim() }; }),
        keptRow: keeper.rowNumber,
        mergedStatus: mergedStatus,
        mergedLastUpload: mergedRow[5]
      });

      if (!dryRun) {
        sheet.getRange(keeper.rowNumber, 1, 1, REG_SHEET_HEADERS.length).setValues([mergedRow]);
        g.forEach(function(r) {
          if (r.rowNumber !== keeper.rowNumber) deletions.push(r.rowNumber);
        });
      }
    });

    if (!dryRun && deletions.length > 0) {
      // Delete bottom-up so earlier row numbers stay valid as rows shift.
      deletions.sort(function(a, b) { return b - a; });
      deletions.forEach(function(rowNum) { sheet.deleteRow(rowNum); });
      report.rowsDeleted = deletions.length;
      SpreadsheetApp.flush();
      invalidateCache_();
      log_('Roster dedupe: merged ' + report.merged.length + ' identity(ies), deleted ' +
           report.rowsDeleted + ' redundant row(s). Backup: ' + report.backupSheet);
    }

    report.verdict = dryRun
      ? 'DRY RUN — nothing written. ' + report.merged.length + ' identity(ies) would collapse, ' +
        'removing ' + (report.merged.reduce(function(s, m) { return s + m.collapsedFrom.length - 1; }, 0)) + ' row(s).'
      : 'Merged ' + report.merged.length + ' identity(ies) and deleted ' + report.rowsDeleted +
        ' row(s). Snapshot saved as hidden sheet "' + report.backupSheet + '".';
    return report;
  } finally {
    lock.releaseLock();
  }
}

function logRosterDedupePlan() {
  Logger.log(JSON.stringify(adminMergeRosterDuplicates(true), null, 2));
}

// v5.1: names-only fleet summary. diagnoseDriveVsRoster returns a full record
// per user, which Apps Script truncates well before the end of a 76-person
// roster — so the rows that matter most (the never-uploaded tail) were exactly
// the ones being cut off. This prints just the names, grouped, so nothing is lost.
function logFleetSummary() {
  var d = diagnoseDriveVsRoster();
  if (d.error) { Logger.log(d.error); return; }

  var byState = { DRIVE_NEWER_THAN_ROSTER: [], NO_DRIVE_FILE: [], IN_SYNC: [] };
  (d.users || []).forEach(function(u) {
    if (byState[u.state]) byState[u.state].push(u.name);
  });

  var lines = [];
  lines.push('FLEET SUMMARY  (' + d.summary.rosterUsers + ' active roster users, ' +
             d.summary.driveFilePairsFound + ' with report files in Drive)');
  lines.push('');
  lines.push('UPLOADING BUT ROSTER STALE — ' + d.summary.driveNewerThanRoster + ' (treat as COMPLIANT):');
  lines.push('  ' + (byState.DRIVE_NEWER_THAN_ROSTER.join(', ') || 'none'));
  lines.push('');
  lines.push('NEVER UPLOADED — ' + d.summary.noDriveFileAtAll + ' (install likely never completed):');
  lines.push('  ' + (byState.NO_DRIVE_FILE.join(', ') || 'none'));
  lines.push('');
  lines.push('ROSTER AGREES WITH DRIVE — ' + d.summary.rosterMatchesDrive +
             ' (accurate; includes long-inactive users)');
  lines.push('');

  // Obvious non-humans left in the roster skew every compliance percentage.
  var suspects = [];
  var reNonHuman = /(^|_)(admin|test|testing|demo|sample|dummy|final)(_|$)/i;
  (d.users || []).forEach(function(u) {
    if (u.state === 'NO_DRIVE_FILE' && reNonHuman.test(u.name)) suspects.push(u.name);
  });
  if (suspects.length > 0) {
    lines.push('LIKELY TEST/NON-HUMAN ENTRIES — ' + suspects.length + ':');
    lines.push('  ' + suspects.join(', '));
    lines.push('  These inflate the compliance denominator. Remove them from the Users page.');
    lines.push('');
  }

  lines.push('Reminder: LastUpload comes from the webhook SUCCESS ping, Drive mtimes come');
  lines.push('from the files themselves. While signatures are being rejected, Drive is the');
  lines.push('only trustworthy record of who is actually reporting.');

  Logger.log(lines.join('\n'));
}

function logRosterDedupeApply() {
  Logger.log(JSON.stringify(adminMergeRosterDuplicates(false), null, 2));
}

// Confirms what the dashboard believes about distribution + digest config,
// without changing anything. Useful right after a setup run.
function logCurrentConfig() {
  Logger.log(JSON.stringify({
    downloadConfig:   getUtilityDownloadConfig(),
    digestConfig:     getWeeklyDigestConfig(),
    adminAllowlist:   getAdminAllowlistInfo(),
    uploadSchedule:   getUploadSchedule_(),
    schemaInfo:       getSchemaInfo()
  }, null, 2));
}
