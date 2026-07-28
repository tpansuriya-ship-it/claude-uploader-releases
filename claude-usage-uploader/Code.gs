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
    sheet.appendRow(['Name', 'QueuedAt', 'QueuedBy', 'Type', 'NotBefore']);
    sheet.getRange(1, 1, 1, 5).setFontWeight('bold');
  } else {
    var lastCol = sheet.getLastColumn();
    if (lastCol < 4) {
      sheet.getRange(1, 4).setValue('Type').setFontWeight('bold');
    }
    if (lastCol < 5) {
      sheet.getRange(1, 5).setValue('NotBefore').setFontWeight('bold');
    }
  }
  return sheet;
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

// Bulk-queue FORCE_RUN for multiple developers in one lock acquisition.
// Skips names already in the queue. Returns { queued: [], skipped: [] }.
function adminQueueTriggerBatch(names) {
  requireAdmin_();
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
        // Stagger each trigger by 60s to prevent simultaneous GAS executions
        var notBefore = new Date(baseTime + queued.length * 60000).toISOString();
        sheet.appendRow([name.trim(), new Date().toISOString(), who, 'FORCE_RUN', notBefore]);
        queued.push(name);
        alreadyQueued[key] = true;
      }
    });
    if (queued.length > 0) {
      log_('TriggerQueue: batch queued ' + queued.length + ' FORCE_RUN(s) by ' + who);
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

function checkAndClearTrigger(name) {
  if (!name) return { triggered: false, paused: false };

  // --- FAST PATH: serve all three pre-checks from CacheService.
  // 99% of calls (idle developers) take this branch with ZERO spreadsheet reads.
  var pausedSet       = getPausedSetCached_();
  var uploadFrequency = getSettingCached_('uploadFrequency', 'weekly');
  var uploadSchedule  = getUploadScheduleCached_();
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
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule };
  }

  // --- SAFE PATH (exclusive lock) ---
  // A row was spotted in cache; acquire the lock and re-read from the sheet before
  // mutating so concurrent requests cannot double-consume the same trigger entry.
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var qSheet = ss.getSheetByName('TriggerQueue');
  if (!qSheet) return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule };

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) {
    log_('checkAndClearTrigger: lock timeout for ' + name);
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule };
  }
  try {
    var data = qSheet.getDataRange().getValues();
    var now2 = new Date();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === nameLower) {
        var nb2 = data[i][4] ? String(data[i][4]).trim() : '';
        if (nb2 && new Date(nb2) > now2) continue; // not yet ready
        var triggerType = data[i][3] ? String(data[i][3]).trim() : 'FORCE_RUN';
        qSheet.deleteRow(i + 1);
        SpreadsheetApp.flush();  // commit immediately so concurrent readers see it gone
        log_('TriggerQueue: consumed ' + triggerType + ' for ' + name);
        invalidateCache_();
        return { triggered: true, type: triggerType, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule };
      }
    }
    // Trigger was claimed by a concurrent request between the cache-check and lock acquisition.
    return { triggered: false, paused: paused, uploadFrequency: uploadFrequency, uploadSchedule: uploadSchedule };
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
var CACHE_TTL_TRIGGERQUEUE = 15;   // trigger queue — 15 seconds (must stay fresh)

function getSettingCached_(key, defaultVal) {
  var c = CacheService.getScriptCache();
  var cacheKey = 'setting_' + key;
  var cached = c.get(cacheKey);
  if (cached !== null) return cached;
  
  var lock = LockService.getScriptLock();
  if (lock.tryLock(5000)) {
    try {
      cached = c.get(cacheKey);
      if (cached !== null) return cached;
      var val = getSetting_(key, defaultVal);
      c.put(cacheKey, String(val), CACHE_TTL_SETTINGS);
      return val;
    } finally {
      lock.releaseLock();
    }
  }
  return defaultVal;
}

// Returns a plain set {lowerCaseName: true} for O(1) lookup.
function getPausedSetCached_() {
  var c = CacheService.getScriptCache();
  var cached = c.get('pausedSet');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch(e) {}
  }
  var lock = LockService.getScriptLock();
  if (lock.tryLock(5000)) {
    try {
      cached = c.get('pausedSet');
      if (cached !== null) {
        try { return JSON.parse(cached); } catch(e) {}
      }
      var map = getPausedDevelopersMap_();
      var set = {};
      Object.keys(map).forEach(function(k) { set[k] = true; });
      try { c.put('pausedSet', JSON.stringify(set), CACHE_TTL_PAUSED); } catch(e) {}
      return set;
    } finally {
      lock.releaseLock();
    }
  }
  return {};
}

// Returns serialised trigger-queue rows so doGet/checkAndClearTrigger
// can check for pending triggers without opening the spreadsheet at all.
function getTriggerQueueRowsCached_() {
  var c = CacheService.getScriptCache();
  var cached = c.get('triggerQueueRows');
  if (cached !== null) {
    try { return JSON.parse(cached); } catch(e) {}
  }
  var lock = LockService.getScriptLock();
  if (lock.tryLock(5000)) {
    try {
      cached = c.get('triggerQueueRows');
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
    } finally {
      lock.releaseLock();
    }
  }
  return [];
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
  
  var lock = LockService.getScriptLock();
  var locked = false;
  try {
    lock.waitLock(10000);
    locked = true;
  } catch (e) {
    throw new Error("Server is generating dashboard data. Please retry in a few moments.");
  }
  
  try {
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
    if (locked) lock.releaseLock();
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
// State lives entirely in CacheService (auto-expires at 24h), so there's no
// permanent state to clean up and no risk of bloating Script Properties.

var AUTOGEN_DELAY_MS = 10 * 60 * 1000;  // 10 minutes after first heartbeat of the day
var AUTOGEN_DEDUP_TTL_S = 23 * 3600;    // cache TTL just under 24h so a new day re-fires

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
    description: 'When a developer is first seen online each day, a FORCE_RUN is queued 10 min later so their report uploads automatically.'
  };
}

function maybeQueueDailyAutoGenerate_(name) {
  if (!getAutoGenerateEnabled_()) return;
  if (!name || name === 'UNKNOWN') return;

  var cache = CacheService.getScriptCache();
  var today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
  var lower = name.trim().toLowerCase();
  var firstSeenKey = 'autogen_firstseen_' + today + '_' + lower;
  var queuedKey    = 'autogen_queued_'    + today + '_' + lower;

  // Already queued today? — nothing to do
  if (cache.get(queuedKey)) return;

  var now = Date.now();
  var firstSeenStr = cache.get(firstSeenKey);
  if (!firstSeenStr) {
    // First heartbeat we've observed today for this user — record and wait
    cache.put(firstSeenKey, String(now), AUTOGEN_DEDUP_TTL_S);
    return;
  }
  var firstSeen = parseInt(firstSeenStr, 10);
  if (!isFinite(firstSeen) || now - firstSeen < AUTOGEN_DELAY_MS) return; // still within the 10-min stabilisation window

  // Cheap pre-checks before grabbing the script lock
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  if (isDeveloperPaused_(ss, name)) {
    cache.put(queuedKey, '1', AUTOGEN_DEDUP_TTL_S); // mark so we don't re-check each heartbeat
    return;
  }

  // Skip if a trigger of any type is already pending for this user
  var queueRows = getTriggerQueueRowsCached_();
  for (var q = 0; q < queueRows.length; q++) {
    if (queueRows[q].name.toLowerCase() === lower) {
      cache.put(queuedKey, '1', AUTOGEN_DEDUP_TTL_S);
      return;
    }
  }

  // Skip if developer already uploaded successfully today (avoids duplicate runs)
  var logSheet = ss.getSheetByName('ComplianceLog');
  if (logSheet) {
    var logData = getRecentLogRows_(logSheet, 200);
    var todayPrefix = today; // YYYY-MM-DD
    for (var i = 0; i < logData.length; i++) {
      var row = logData[i];
      if (!row[0]) continue;
      var rName = String(row[1] || '').trim().toLowerCase();
      if (rName !== lower) continue;
      var status = String(row[3] || '').trim().toUpperCase();
      if (status !== 'SUCCESS') continue;
      var ts = row[0];
      var tsStr = (ts && typeof ts.toISOString === 'function')
        ? Utilities.formatDate(ts, Session.getScriptTimeZone(), 'yyyy-MM-dd')
        : String(ts).substring(0, 10);
      if (tsStr === todayPrefix) {
        // Already uploaded today — mark queued so we don't re-check until tomorrow
        cache.put(queuedKey, '1', AUTOGEN_DEDUP_TTL_S);
        return;
      }
    }
  }

  // Queue the trigger under lock (race-safe — same pattern as SmartRetry)
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return;
  try {
    // Re-check queue inside the lock
    var qSheet = ensureTriggerQueue();
    var freshData = qSheet.getDataRange().getValues();
    for (var j = 1; j < freshData.length; j++) {
      if (String(freshData[j][0]).trim().toLowerCase() === lower) {
        cache.put(queuedKey, '1', AUTOGEN_DEDUP_TTL_S);
        return;
      }
    }
    var who = 'system:autoDaily';
    var notBefore = new Date().toISOString();
    qSheet.appendRow([name.trim(), new Date().toISOString(), who, 'FORCE_RUN', notBefore]);
    SpreadsheetApp.flush();
    cache.put(queuedKey, '1', AUTOGEN_DEDUP_TTL_S);
    log_('AutoDaily: queued FORCE_RUN for ' + name + ' (first online today ' + Math.round((now - firstSeen) / 60000) + ' min ago)');
    invalidateCache_();
  } finally {
    lock.releaseLock();
  }
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

    var ss    = SpreadsheetApp.getActiveSpreadsheet();

    var isNoise = NOISE_STATUSES.indexOf(status) !== -1;

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
      if (!throttleActive) {
        upsertRosterActivity_(name, status, version, nextPollAt, lastUpdateCheck);
      }
    }

    if (!isNoise) {
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
    time: normalizeUploadTime_(getSetting_('globalUploadTime', '13:00')),
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
  setSettingValue_(sheet, 'globalUploadTime', time);
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
function forceSendUpdateBatch(names) {
  requireAdmin_();
  if (!Array.isArray(names) || names.length === 0) return { success: false, error: 'No names provided' };
  var ok = 0, fail = 0, errors = [];
  names.forEach(function(n) {
    try {
      var r = adminQueueTrigger(n, 'UPDATE');
      if (r && r.success) ok++; else { fail++; errors.push(n + ': ' + (r && r.error || 'unknown')); }
    } catch (e) {
      fail++; errors.push(n + ': ' + e.toString());
    }
  });
  return { success: fail === 0, queued: ok, failed: fail, errors: errors };
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
      'Claude Usage Uploader utility on your {{system}} machine.\n\n' +
      'Download (v{{latestVersion}}):\n{{downloadUrl}}\n\n' +
      'Setup takes about a minute:\n' +
      '  1. Download and run the installer.\n' +
      '  2. Enter your first and last name exactly as "{{name}}" when prompted.\n' +
      '  3. Leave it running — it reports automatically in the background.\n\n' +
      'If the installer reports that it could not register the scheduled task, ' +
      'right-click it and choose "Run as Administrator".\n\n' +
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
    GmailApp.sendEmail(user.email, subject, body);
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
var SETUP_LATEST_VERSION = '2.0.6';

// Public download links. Must be https://. These 404 until CI publishes the release.
//
// v2.0.6 moves releases to tpansuriya-ship-it — the same account that owns the
// update manifest Gist, so the manifest and the binaries it points at finally live
// together. Up to v2.0.5 releases were published under
// Nishantjha1997/claude-uploader-releases, a personal account we only have read
// access to, so `git push` returned 403 and no release could be cut at all.
// Older assets stay reachable there (that repo is public), so existing installs
// keep working; only new releases move.
var SETUP_DOWNLOAD_URLS = {
  windows: 'https://github.com/tpansuriya-ship-it/claude-uploader-releases/releases/download/v2.0.6/ClaudeUsageUploader_v2.0.6-win-x64.exe',
  macos:   'https://github.com/tpansuriya-ship-it/claude-uploader-releases/releases/download/v2.0.6/ClaudeUsageUploader_v2.0.6-macos-arm64',
  linux:   'https://github.com/tpansuriya-ship-it/claude-uploader-releases/releases/download/v2.0.6/ClaudeUsageUploader_v2.0.6-linux-x64'
};

// Who receives the Monday 12:00 IST digest. REPLACE THESE PLACEHOLDERS — they
// are intentionally invalid so a typo can never silently mail the wrong person.
var SETUP_DIGEST_RECIPIENTS = 'REPLACE_dhairya@sigmasolve.com, REPLACE_tejas@sigmasolve.com';

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
  setSettingValue_(sheet, 'globalUploadTime', '00:00');
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
