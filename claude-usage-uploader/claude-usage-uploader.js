// Claude Usage Uploader — Cross-Platform Version
// ================================================================
// TO BUILD:
//   Windows:      npx pkg claude-usage-uploader.js --target node16-win-x64 --output ClaudeUsageUploader.exe
//   macOS x64:    npx pkg claude-usage-uploader.js --target node16-macos-x64 --output ClaudeUsageUploader-mac-x64
//   macOS arm64:  npx pkg claude-usage-uploader.js --target node16-macos-arm64 --no-bytecode --public --public-packages "*" --output ClaudeUsageUploader-mac-arm64
//                 Then on a Mac: codesign --sign - ClaudeUsageUploader-mac-arm64
//   Linux x64:    npx pkg claude-usage-uploader.js --target node16-linux-x64 --output ClaudeUsageUploader-linux-x64
// ================================================================

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const os = require('os');
const readline = require('readline');
const https = require('https');
const crypto = require('crypto');
const nodeFetch = require('node-fetch');
const { Headers, Request, Response } = nodeFetch;

if (typeof global.fetch === 'undefined') global.fetch = nodeFetch;
if (typeof global.Headers === 'undefined') global.Headers = Headers;
if (typeof global.Request === 'undefined') global.Request = Request;
if (typeof global.Response === 'undefined') global.Response = Response;

if (typeof globalThis !== 'undefined') {
  if (typeof globalThis.fetch === 'undefined') globalThis.fetch = nodeFetch;
  if (typeof globalThis.Headers === 'undefined') globalThis.Headers = Headers;
  if (typeof globalThis.Request === 'undefined') globalThis.Request = Request;
  if (typeof globalThis.Response === 'undefined') globalThis.Response = Response;
}

// -------------------- PLATFORM --------------------
const IS_WIN   = process.platform === 'win32';
const IS_MAC   = process.platform === 'darwin';
const IS_LINUX = process.platform === 'linux';
const PLATFORM_KEY = IS_WIN ? 'win32' : IS_MAC ? 'darwin' : 'linux';

// -------------------- CONFIGURATION --------------------
const VERSION = '2.0.7';
const FORCE_RUN = process.argv.includes('--force');
const IS_SCHEDULED = process.argv.includes('--scheduled');
const UPDATED_FROM = (() => {
  const arg = process.argv.find(a => a.startsWith('--updated-from='));
  return arg ? arg.substring('--updated-from='.length).replace(/[^0-9A-Za-z._-]/g, '') : '';
})();

// -------------------- SERVICE LOOP INTERVALS --------------------
const POLL_INTERVAL_MS      = 60  * 1000;         // poll for admin triggers every 60s (v2.1: was 5s — cuts GAS doGet executions ~91.6%)
const HEARTBEAT_INTERVAL_MS =  5  * 60 * 1000;    // heartbeat every 5 minutes
const UPLOAD_CHECK_MS       = 60  * 60 * 1000;    // check if upload due every hour
const UPDATE_CHECK_MS       = 60  * 60 * 1000;     // retry update discovery every hour

const MANIFEST_URL = 'https://gist.githubusercontent.com/tpansuriya-ship-it/efa5db7d25aaa85db78d8bdc402f9903/raw/version.json';

// Shared HMAC secret between uploader and GAS webhook endpoint.
// GAS validates the _sig query parameter on every incoming request.
//
// v2.0.6: rotated. The previous value shipped in this public repository for
// several releases, so anyone could forge pings for any developer name. The GAS
// side accepts BOTH this value and the retired one (see WEBHOOK_HMAC_SECRET_RETIRED
// in Code.gs) until the fleet has self-updated, then the old one is removed.
//
// NOTE: this constant is still committed, so it is only as private as the repo.
// The durable fix is to inject it at build time from a CI secret and keep it out
// of source entirely.
const WEBHOOK_HMAC_SECRET = 'ss-uploader-hmac-2026b-cab69d71b7b5cc93fe49e24818bc8cc2';

// v2.0.7: the Drive upload target is now SERVER-CONTROLLED.
//
// Up to v2.0.6 this was a hardcoded constant, so relocating the report folder
// meant rebuilding the binary and pushing it to every machine — including the
// dormant ones that never self-update. The server now sends `driveFolderId` on
// every trigger poll, so the folder can be changed from the dashboard alone.
//
// This constant remains the fallback, used when the server sends nothing, sends
// something malformed, or when the configured folder turns out to be unwritable.
// Reporting must never stop because of a bad configuration value.
const DRIVE_FOLDER_ID_DEFAULT = '0AMXBcPT9R10cUk9PVA';

// The folder actually in use. Updated by the poll loop, persisted to config so a
// restart before the first successful poll still uses the last known-good value.
let activeDriveFolderId = DRIVE_FOLDER_ID_DEFAULT;

// Drive IDs are URL-safe base64-ish. Anything else is a typo or an injected
// value and must not reach a Drive query, so we reject it and keep the default.
function isPlausibleDriveFolderId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{10,80}$/.test(id.trim());
}

// Returns the folder to upload into. Single source of truth for the whole
// upload path — never read the constant directly.
function getDriveFolderId() {
  return activeDriveFolderId || DRIVE_FOLDER_ID_DEFAULT;
}

// Apply a server-sent folder. Returns true if the effective value changed.
// `persist` writes it to config.json so it survives a restart.
function applyServerDriveFolderId(id, persist = true) {
  const next = (id == null ? '' : String(id)).trim();
  if (!next) return false;                       // server said nothing — keep current
  if (next === activeDriveFolderId) return false; // no change
  if (!isPlausibleDriveFolderId(next)) {
    log(`Ignoring implausible driveFolderId from server: "${next.slice(0, 40)}"`);
    return false;
  }
  const previous = activeDriveFolderId;
  activeDriveFolderId = next;
  log(`Drive folder changed by server: ${previous} -> ${next}`);
  if (persist) {
    try {
      const cfg = loadConfig();
      if (cfg) {
        cfg.driveFolderId = next;
        const tmp = CONFIG_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(cfg));
        fs.renameSync(tmp, CONFIG_FILE);
      }
    } catch (e) {
      log(`Could not persist driveFolderId: ${e.message}`);
    }
  }
  return true;
}

// Revert to the compiled default after a permissions/not-found failure on the
// configured folder, so a mistyped folder in the dashboard degrades to "uploads
// still work, in the old place" instead of "the whole fleet stops reporting".
function revertDriveFolderToDefault(reason) {
  if (activeDriveFolderId === DRIVE_FOLDER_ID_DEFAULT) return false;
  log(`CRITICAL: falling back to the default Drive folder (${DRIVE_FOLDER_ID_DEFAULT}) — ${reason}`);
  activeDriveFolderId = DRIVE_FOLDER_ID_DEFAULT;
  return true;
}
let globalCcusageJsPath = '';
let globalCcusageBinPath = '';
const SERVICE_KEY_FILE = 'service-account-key.json';
const WEBHOOK_URL = 'https://script.google.com/macros/s/AKfycby9bFBRwYLu1GF6urQn3saAuVacI95NjS2Jt2G3eiba3StKwu9i8POjXnlx224NMMXt/exec';

// When packaged with pkg, process.execPath is the binary; otherwise use __dirname
const EXE_DIR = process.pkg ? path.dirname(process.execPath) : __dirname;
const GOOGLE_KEY_FILE = path.join(EXE_DIR, SERVICE_KEY_FILE);

// Cross-platform config directory
const CONFIG_DIR = IS_WIN
  ? path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'ClaudeUsageUploader')
  : path.join(os.homedir(), '.config', 'ClaudeUsageUploader');

const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const LOG_FILE = path.join(os.tmpdir(), 'claude-uploader.log');
const RETRY_QUEUE_FILE   = path.join(CONFIG_DIR, 'upload-queue.json');
const FAILED_PINGS_FILE  = path.join(CONFIG_DIR, 'failed-pings.ndjson');
const EVENTS_LOG_FILE    = path.join(CONFIG_DIR, 'events.ndjson');
const HEALTH_FILE        = path.join(CONFIG_DIR, 'service.heartbeat');
const PING_TIMEOUT_MS    = 10000;
const PING_MAX_ATTEMPTS  = 3;
const EVENTS_ROTATE_BYTES      = 5 * 1024 * 1024;   // 5 MB
const FAILED_PINGS_WARN_BYTES  = 10 * 1024 * 1024;  // 10 MB

let lastUpdateCheckAt = null;

// -------------------- DURABLE EVENT LOG + PING REPLAY QUEUE --------------------
function appendEvent(entry) {
  try {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
    // Rotate at 5 MB: keep one backup
    try {
      const stat = fs.existsSync(EVENTS_LOG_FILE) && fs.statSync(EVENTS_LOG_FILE);
      if (stat && stat.size > EVENTS_ROTATE_BYTES) {
        try { fs.unlinkSync(EVENTS_LOG_FILE + '.1'); } catch {}
        fs.renameSync(EVENTS_LOG_FILE, EVENTS_LOG_FILE + '.1');
      }
    } catch {}
    fs.appendFileSync(EVENTS_LOG_FILE, line);
  } catch {}
}

// Returns true if enqueue succeeded, false if the disk write failed.
function enqueueFailedPing({ payload, firstAttemptAt, lastAttemptAt }) {
  try {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const line = JSON.stringify({ id, payload, firstAttemptAt, lastAttemptAt }) + '\n';
    fs.appendFileSync(FAILED_PINGS_FILE, line);
    try {
      const stat = fs.statSync(FAILED_PINGS_FILE);
      if (stat.size > FAILED_PINGS_WARN_BYTES) log('WARNING: failed-pings.ndjson exceeds 10 MB — check GAS connectivity');
    } catch {}
    return true;
  } catch (e) {
    log(`enqueueFailedPing write error: ${e.message}`);
    return false;
  }
}

function loadFailedPings() {
  if (!fs.existsSync(FAILED_PINGS_FILE)) return [];
  const entries = [];
  try {
    const lines = fs.readFileSync(FAILED_PINGS_FILE, 'utf8').split('\n');
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      try { entries.push(JSON.parse(line)); }
      catch { log(`loadFailedPings: skipping malformed entry`); }
    }
  } catch (e) { log(`loadFailedPings read error: ${e.message}`); }
  return entries;
}

function rewriteFailedPings(entries) {
  try {
    const content = entries.map(e => JSON.stringify(e)).join('\n') + (entries.length ? '\n' : '');
    const tmp = FAILED_PINGS_FILE + '.tmp';
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, FAILED_PINGS_FILE);
  } catch (e) { log(`rewriteFailedPings error: ${e.message}`); }
}

// -------------------- SETUP GUI HTML --------------------
const SIGMA_SVG = `<img src="data:image/png;base64,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6P8yF1ewrYVJ6IwQERERERGNlojMRGQl/bMS28JJREREREREXREbJC4DB4QiNg+z0MeDiIiIiIhor4nIiYicS7etiUsRORPb1ZWIiIioVPMxh0RE5M0Fa5H7mUBnfOIVgBXgJpgClpx9lIiIiKpicEhE1BMuYJy4P3dN8LVyPwCwMsasSt9JRERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERUkwmdASIiIiKiPhCRCMAEwCGAJQAYY5JwOSLqFoNDop4RkQnsjekD3piIqA3uQfgMwCMAbwGchyhvROQQwEnu5aUx5qbrvITgPn+Eu2MQAbiBC04AJNij49E1d/zPAUwBHBS9xxiz9ZlZRGaw19IEwALA3Biz0sznjv1PwGcHIqLxEZG55ITOExGNj4gcishNrrgJEnyISJQv91zgOmoiMhORpOCzl1nsw3HpkoicFFwHeUmFNLy20SZ8diAlvxI6A0RERBREUSvJgdgWEGqRC4ZXAN4AOPXY9BGAdy6gzLe0kiexLYYLlLQWZix2/P9ZwWunYlvziAblG6EzQEREw+SCiEnmpZUxJg6SGapj5fn6BteKFWW35TmwnYjMAbxomMwpgEREzni8G5kBOCp4/Qq2K+8J7NjDZEc6q4LX1rBdg4mIiOpj1xAaCtnsDpeEzhP5afodFpRXXttn0tmLbqUiEhd8zqwb951kf3Z1eZyF/lxDVXD+i4hMa6RT1EV73kKWt+WBzw6kgi2HREREe8oYE7ngIgKwMMbs6j5HNYlIDOBpyX9fwE4GtCz6Txcoz0q2fyMiN/zuasl36X1b5zgaY27EdiGdwl5Lpd8lUd8xOCQiItpjrltiHDgbo+Zao4oCuysA012zWrpZJxMXYBaNkYtFZMLZTBurHdC5Yx+D1xINHCekISIiImqJ2ElP4oL/ugAQ+Sx34ILECHY8W9YB7FIMRESNMDgkIiIias8ZNlv6rgCc1Wnpc90VI2wGiE+Fs2MSUUPsVko0MrK5EO4qXzMtmzMMAna2taTpor0Fk0jcW7jZ1aJPc3lM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Rnuh9cwCMDgkopEyxswBfILNgf7bXAN47IJLTXHBa1cakze4m5HP51zDfsak6b4z+3+G7Q80lQIDY8yNu8HtSi9vDfugfNLzh9SiQK5ScFeyXmLl7dvkHih3fWdRN7npP3eeT2Gv2zrrAl4A+LYr4zTys4C9Rn3yMpRrblDcPWGC6pUHVwBU17ateT7Avf87QwwMU+7e/xj+zw2fNPnc7vuLsD04Ldv3Y83AEAC+oZkYEalIlLdfeW6/wmarm08aTbYFbCCVNNj+AxcATcT2w5/B3vDyNZ5rt79Fize1c2zW6iZaiWc+5wy29S3CZg3nFeyxjTMPczEUjrUxJhY75mjm9p3tYrbyTdd9D/GOz7OGnQ1vgfufqc8SbF4fPsHdGXKBds2ZbrNi6J4DU/eTPQdusPt8X6FHZUcX3HUbiR1XlB63CTbLqGvYcz2BLadWLeRlhbv1N2ew11xRS8UldK65Fbb37qgiv30SKA3VtNxxTZc9OoP9LvLnxBXsuTDPvLYqyEMtHufDFeznjBsGqL259l1wvNhx/7nG3fWoUkGX9sQRO9wkLQ+Kesqk5UGbzyxERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERPf9H7ZyMf2eYiq0AAAAAElFTkSuQmCC" alt="SigmaSolve" style="max-width:200px;height:64px;object-fit:contain;display:block;margin:0 auto">`;

const SETUP_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Usage Uploader — Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',Tahoma,sans-serif;padding:20px}
.card{background:#fff;border-radius:20px;padding:44px 40px;width:480px;box-shadow:0 24px 80px rgba(0,0,0,.45)}
.logo-row{text-align:center;margin-bottom:20px}
.logo-row svg{max-width:180px;height:auto}
h1{font-size:20px;font-weight:700;color:#1a1a2e;margin-bottom:4px;text-align:center;margin-top:10px}
.sub{font-size:13px;color:#888;text-align:center;margin-bottom:16px}
.badge{display:inline-block;background:#eef0ff;color:#4361ee;font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;margin-bottom:20px}
.field{margin-bottom:16px}
.field-row{display:flex;gap:12px;margin-bottom:16px}
.field-row .field{flex:1;margin-bottom:0}
label{display:block;font-size:13px;font-weight:600;color:#333;margin-bottom:7px}
input{width:100%;padding:12px 14px;border:2px solid #e8e8e8;border-radius:10px;font-size:14px;transition:border-color .2s;outline:none;color:#1a1a2e}
input:focus{border-color:#4361ee}
input.err{border-color:#e63946}
.hint{font-size:11px;color:#999;margin-top:8px;line-height:1.5}
.err-msg{color:#e63946;font-size:12px;margin-top:5px;display:none}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#4361ee,#3a0ca3);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;margin-top:8px;transition:opacity .2s}
.btn:hover:not(:disabled){opacity:.88}
.btn:disabled{opacity:.5;cursor:not-allowed}
.result{display:none;margin-top:20px;padding:16px;border-radius:12px;font-size:13px;line-height:1.6}
.result.ok{background:#edfdf4;border:1.5px solid #2d6a4f;color:#2d6a4f}
.result.fail{background:#fff0f0;border:1.5px solid #e63946;color:#c0392b}
.result h3{font-size:15px;margin-bottom:6px}
.success{display:none;text-align:center;padding:10px 0}
.check{font-size:64px;display:block;margin-bottom:12px}
.success h2{color:#2d6a4f;font-size:22px;margin-bottom:10px}
.success p{color:#666;font-size:14px;line-height:1.7}
</style>
</head>
<body>
<div class="card">
  <div class="logo-row">
    ${SIGMA_SVG}
    <h1>Claude Usage Uploader</h1>
    <p class="sub">One-time setup &mdash; takes 30 seconds</p>
    <span class="badge">v${VERSION}</span>
  </div>
  <div id="formView">
    <form id="setupForm" onsubmit="doSubmit(event)">
      <div class="field-row">
        <div class="field">
          <label>First Name <span style="color:#e63946">*</span></label>
          <input id="firstNameInput" type="text" placeholder="e.g. Nishant" autocomplete="given-name" required>
          <div class="err-msg" id="firstErr">Required.</div>
        </div>
        <div class="field">
          <label>Last Name <span style="color:#e63946">*</span></label>
          <input id="lastNameInput" type="text" placeholder="e.g. Jha" autocomplete="family-name" required>
          <div class="err-msg" id="lastErr">Required.</div>
        </div>
      </div>
      <p class="hint">Your name must match what is registered with your admin. It will be used to name your uploaded files.</p>
      <button class="btn" type="submit" id="submitBtn">Complete Setup &#8594;</button>
    </form>
    <div class="result" id="taskResult"></div>
  </div>

  <div class="success" id="successView">
    <span class="check">&#9989;</span>
    <h2>Setup Complete!</h2>
    <p>Your configuration has been saved.<br>
    The background service is now running and will upload your Claude usage every week automatically.<br><br>
    You can close this window.</p>
  </div>
</div>
<script>
const firstEl=document.getElementById('firstNameInput');
const lastEl=document.getElementById('lastNameInput');
firstEl.focus();
async function doSubmit(e){
  e.preventDefault();
  const firstName=firstEl.value.trim();
  const lastName=lastEl.value.trim();
  let ok=true;
  if(!firstName){document.getElementById('firstErr').style.display='block';firstEl.classList.add('err');ok=false;}else{document.getElementById('firstErr').style.display='none';firstEl.classList.remove('err');}
  if(!lastName){document.getElementById('lastErr').style.display='block';lastEl.classList.add('err');ok=false;}else{document.getElementById('lastErr').style.display='none';lastEl.classList.remove('err');}
  if(!ok) return;
  const btn=document.getElementById('submitBtn');
  btn.disabled=true;btn.textContent='Setting up\u2026';
  try{
    const r=await fetch('/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({firstName,lastName})});
    if(r.ok){
      const txt=await r.text();
      const data=JSON.parse(txt);
      showTaskResult(data);
      if(data.taskOk){setTimeout(()=>{document.getElementById('formView').style.display='none';document.getElementById('successView').style.display='block';},2200);}
      else{btn.disabled=false;btn.textContent='Complete Setup \u2192';}
    } else {
      btn.disabled=false;btn.textContent='Complete Setup \u2192';alert('Setup failed. Please try again.');
    }
  }catch(err){btn.disabled=false;btn.textContent='Complete Setup \u2192';alert('Error: '+err.message);}
}
function showTaskResult(data){
  const el=document.getElementById('taskResult');
  if(data.taskOk){
    el.className='result ok';
    el.innerHTML='<h3>&#10003; Background service registered!</h3>The scheduled task was created successfully. The uploader will start automatically on every login.';
  } else {
    el.className='result fail';
    el.innerHTML='<h3>&#9888; Task registration failed</h3><b>Reason:</b> '+data.taskError+'<br><br><b>What to do:</b> Close this window, then right-click the <b>ClaudeUsageUploader.exe</b> file and choose <b>Run as Administrator</b>.';
  }
  el.style.display='block';
}
</script>
</body>
</html>`;

const MAX_RETRIES = 3;
const CMD_TIMEOUT = 30000;
const CCUSAGE_TIMEOUT_MS = 60000;

// -------------------- ERROR CODE TAXONOMY --------------------
const ERR = Object.freeze({
  CCUSAGE_NOT_FOUND:    'CCUSAGE_NOT_FOUND',
  CCUSAGE_TIMEOUT:      'CCUSAGE_TIMEOUT',
  CCUSAGE_EMPTY_OUTPUT: 'CCUSAGE_EMPTY_OUTPUT',
  CCUSAGE_INVALID_JSON: 'CCUSAGE_INVALID_JSON',
  CCUSAGE_FAILED:       'CCUSAGE_FAILED',
  AUTH_KEY_MISSING:     'AUTH_KEY_MISSING',
  DRIVE_AUTH_FAILED:    'DRIVE_AUTH_FAILED',
  DRIVE_RATE_LIMITED:   'DRIVE_RATE_LIMITED',
  DRIVE_QUOTA_EXCEEDED: 'DRIVE_QUOTA_EXCEEDED',
  DRIVE_UPLOAD_FAILED:  'DRIVE_UPLOAD_FAILED',
  DRIVE_VERIFY_FAILED:  'DRIVE_VERIFY_FAILED',
  CREDENTIALS_MISSING:  'CREDENTIALS_MISSING',
  WATCHDOG_STALL:       'WATCHDOG_STALL',
  NO_DATA:              'NO_DATA',
  UNKNOWN_ERROR:        'UNKNOWN_ERROR',
});

let globalNodeDir = '';

// -------------------- LOGGING --------------------
function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    if (fs.existsSync(LOG_FILE)) {
      const stats = fs.statSync(LOG_FILE);
      if (stats.size > 5 * 1024 * 1024) { // 5MB
        fs.renameSync(LOG_FILE, LOG_FILE + '.1');
      }
    }
    fs.appendFileSync(LOG_FILE, line);
  } catch {}
}

// -------------------- COMMAND EXECUTION --------------------
function run(cmd, customOpts = {}) {
  log(`CMD: ${cmd}`);
  try {
    const result = execSync(cmd, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: CMD_TIMEOUT,
      ...customOpts
    });
    return result.trim();
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString().trim() : '';
    if (stderr) log(`STDERR: ${stderr}`);
    if (err.killed) {
      log(`Command timed out after ${CMD_TIMEOUT / 1000}s: ${cmd}`);
      throw new Error(`Command timed out: ${cmd}`);
    }
    throw err;
  }
}

// Async ccusage runner — spawn + 60s hard timeout; never blocks the event loop.
function runCcusage(cmd, outFile, envOpts) {
  return new Promise((resolve, reject) => {
    // Quote-aware split so paths like "C:\Program Files\..." are kept as one token.
    // Strip surrounding quotes after splitting — spawn takes raw paths, not shell-quoted ones.
    const parts = (cmd.match(/(?:[^\s"]+|"[^"]*")+/g) || []).map(p => p.replace(/^"|"$/g, ''));
    const bin   = parts[0];
    const args  = parts.slice(1);
    const env   = (envOpts && envOpts.env) ? envOpts.env : process.env;
    let timedOut = false;

    const child = spawn(bin, args, {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, CCUSAGE_TIMEOUT_MS);

    const outStream = fs.createWriteStream(outFile);
    child.stdout.pipe(outStream);
    let stderr = '';
    child.stderr.on('data', d => { stderr += d; });
    child.on('error', err => {
      clearTimeout(timer);
      if (err.code === 'EPERM') {
        reject(new Error(`${ERR.CCUSAGE_FAILED}: Permission denied (EPERM). Antivirus may be blocking shell access.`));
      } else if (err.code === 'ENOENT') {
        reject(new Error(`${ERR.CCUSAGE_NOT_FOUND}: ccusage not found in PATH`));
      } else {
        reject(new Error(`${ERR.CCUSAGE_FAILED}: ${err.message}`));
      }
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`${ERR.CCUSAGE_TIMEOUT}: ccusage timed out after ${CCUSAGE_TIMEOUT_MS / 1000}s`));
        return;
      }
      if (code !== 0) {
        const detail = stderr.trim() || `exit code ${code}`;
        reject(new Error(`${ERR.CCUSAGE_FAILED}: ccusage exited ${code}; ${detail}`));
        return;
      }
      resolve();
    });
  });
}

// -------------------- PING --------------------
// extra: optional object with additional fields (e.g. { nextPollAt })

// Single attempt — resolves {ok, status, body}, never rejects.
// HMAC signature sent as ?_ts=<unix>&_sig=<hex> so GAS doPost can read via e.parameter.
function sendPingOnce(payload) {
  return new Promise((resolve) => {
    const data = JSON.stringify(payload);
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = crypto.createHmac('sha256', WEBHOOK_HMAC_SECRET)
      .update(ts + '.' + data)
      .digest('hex');
    const url = new URL(WEBHOOK_URL);
    url.searchParams.set('_ts', ts);
    url.searchParams.set('_sig', sig);
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
      timeout: PING_TIMEOUT_MS,
    };
    const checkBody = (statusCode, rawBody) => {
      // If GAS rejected the signature it returns a JSON error body.
      // Detect it regardless of HTTP status so a silent rejection surfaces loudly.
      try {
        const parsed = JSON.parse(rawBody);
        if (parsed.result === 'error') {
          if (parsed.error === 'invalid_signature') {
            log(`CRITICAL: GAS rejected webhook signature (${parsed.reason || parsed.error}). ` +
                `Check the deployment's "Who has access" is set to Anyone, and that the ` +
                `system clock is within 5 minutes of real time.`);
          }
          return { ok: false, status: statusCode, body: rawBody };
        }
        return { ok: true, status: statusCode, body: rawBody };
      } catch (_) {
        // v2.0.6: a non-JSON body is a FAILURE, not a success.
        //
        // doPost always answers with JSON. Anything else means the request never
        // reached it — overwhelmingly an HTML sign-in page, because the web-app
        // deployment is restricted rather than "Anyone". The old code returned
        // ok:true here, so the agent believed every ping was delivered while the
        // server recorded nothing: the entire fleet read as Offline for weeks with
        // not one line in any log. Failing here lets the retry queue engage and
        // puts the cause in the local log.
        const snippet = String(rawBody || '').replace(/\s+/g, ' ').slice(0, 120);
        const looksLikeLogin = /<html|sign in|accounts\.google\.com/i.test(rawBody || '');
        log(`CRITICAL: webhook returned non-JSON (HTTP ${statusCode})` +
            (looksLikeLogin
              ? ' — this is a Google sign-in page. Set the web-app deployment access to "Anyone".'
              : ` — first bytes: ${snippet}`));
        return { ok: false, status: statusCode, body: rawBody };
      }
    };

    const req = https.request(options, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
          // v2.0.6: RE-POST the body on redirect.
          //
          // Apps Script /exec answers POSTs with a 302 to script.googleusercontent.com.
          // Up to v2.0.5 this followed that redirect with https.get() — a GET with no
          // body. The _ts/_sig query params survived, but the payload did not, so GAS
          // hashed ts+'.'+'' while we had signed ts+'.'+data. Every such ping was
          // rejected as `sig_mismatch`, which sent everyone hunting for a wrong secret
          // when the real problem was a discarded request body.
          //
          // Re-issuing as a POST with the same body and headers keeps the signature
          // valid across the hop.
          let loc;
          try {
            loc = new URL(res.headers.location, WEBHOOK_URL);
          } catch (_) {
            resolve({ ok: false, status: res.statusCode, body: 'unparseable redirect location' });
            return;
          }
          const r2Options = {
            hostname: loc.hostname,
            port: loc.port || 443,
            path: loc.pathname + loc.search,
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(data),
            },
            timeout: PING_TIMEOUT_MS,
          };
          const r2Req = https.request(r2Options, r2 => {
            let b2 = '';
            r2.on('data', c => { b2 += c; });
            r2.on('end', () => resolve(checkBody(r2.statusCode, b2)));
          });
          // A failed redirect hop is a failed ping. Reporting ok:true here (as
          // v2.0.5 did) is what made delivery failures invisible.
          r2Req.on('error', (e) => resolve({ ok: false, status: 0, body: 'redirect hop failed: ' + e.message }));
          r2Req.on('timeout', () => { r2Req.destroy(); resolve({ ok: false, status: 0, body: 'redirect hop timeout' }); });
          r2Req.write(data);
          r2Req.end();
          return;
        }
        resolve(checkBody(res.statusCode, body));
      });
    });
    req.on('error', (err) => resolve({ ok: false, status: 0, body: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, body: 'timeout' }); });
    req.write(data);
    req.end();
  });
}

// Retry wrapper — 3 attempts with jittered backoff; queues to disk on final failure.
// Returns {ok, status, body, queued} — never throws.
async function sendPing(name, status, message = '', extra = {}) {
  const payload = { name, status, message, ...extra };
  const firstAttemptAt = new Date().toISOString();
  let lastResult = { ok: false, status: 0, body: '' };

  for (let attempt = 1; attempt <= PING_MAX_ATTEMPTS; attempt++) {
    lastResult = await sendPingOnce(payload);
    appendEvent({ kind: 'ping', name, status, message, attempt, httpStatus: lastResult.status, ok: lastResult.ok });
    if (lastResult.ok) {
      log(`Ping sent: ${name} ${status}`);
      return { ...lastResult, queued: false };
    }
    log(`Ping attempt ${attempt}/${PING_MAX_ATTEMPTS} failed (${lastResult.status || lastResult.body}): ${name} ${status}`);
    if (attempt < PING_MAX_ATTEMPTS) {
      const delay = Math.floor(1000 * Math.pow(2, attempt - 1) * (1 + Math.random()));
      await new Promise(r => setTimeout(r, delay));
    }
  }

  // All attempts failed — queue durably for replay
  const queued = enqueueFailedPing({ payload, firstAttemptAt, lastAttemptAt: new Date().toISOString() });
  log(`Ping queued for replay: ${name} ${status} (queued=${queued})`);
  return { ...lastResult, queued };
}

// -------------------- AUTO-UPDATE --------------------
function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const doRequest = (targetUrl, redirectsLeft) => {
      if (redirectsLeft < 0) return reject(new Error('Too many manifest redirects'));

      const requestUrl = new URL(targetUrl);
      // The unversioned Gist raw URL is served through a CDN. A unique query
      // prevents a recently published manifest from being hidden by a stale edge.
      requestUrl.searchParams.set('_updateCheck', Date.now().toString());

      https.get(requestUrl, {
        headers: {
          'Cache-Control': 'no-cache, no-store',
          'Pragma': 'no-cache',
          'User-Agent': `ClaudeUsageUploader/${VERSION}`,
        },
      }, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode)) {
          res.resume();
          if (!res.headers.location) return reject(new Error('Manifest redirect has no Location header'));
          return doRequest(new URL(res.headers.location, requestUrl).toString(), redirectsLeft - 1);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error('Manifest status: ' + res.statusCode));
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(e); }
        });
      }).on('error', reject);
    };

    doRequest(url, 5);
  });
}

function vbsString(value) {
  return String(value).replace(/"/g, '""');
}

function releaseBinaryName(version) {
  const safeVersion = String(version).replace(/[^0-9A-Za-z._-]/g, '');
  if (IS_WIN) return `ClaudeUsageUploader_v${safeVersion}-win-x64.exe`;
  if (IS_MAC) return `ClaudeUsageUploader_v${safeVersion}-${process.arch === 'arm64' ? 'macos-arm64' : 'macos-x64'}`;
  return `ClaudeUsageUploader_v${safeVersion}-linux-x64`;
}

function manifestPlatformKeys(platform = process.platform, arch = process.arch) {
  if (platform === 'win32') return [`win32-${arch}`, 'win32'];
  if (platform === 'darwin') return [`darwin-${arch}`, 'darwin'];
  if (platform === 'linux') return [`linux-${arch}`, 'linux'];
  return [`${platform}-${arch}`, platform];
}

function launchSilentWindowsUpdater(tempBinPath, newVersion) {
  const updaterPath = path.join(os.tmpdir(), `claude-uploader-update-${process.pid}.vbs`);
  // Install beside the running executable. Replacing an in-use .exe is the
  // root cause of the v2.0.1 -> v2.0.3 update loop seen in production.
  const targetBinPath = path.join(EXE_DIR, releaseBinaryName(newVersion));
  const moveCommand = `cmd.exe /d /s /c "move /Y ""${tempBinPath}"" ""${targetBinPath}"" >nul 2>&1"`;
  const launchCommand = `"${targetBinPath}" --updated-from=${VERSION}`;
  const script = [
    'Option Explicit',
    'Dim shell, fso, exitCode',
    'Set shell = CreateObject("WScript.Shell")',
    'Set fso = CreateObject("Scripting.FileSystemObject")',
    'WScript.Sleep 5000',
    `exitCode = shell.Run("${vbsString(moveCommand)}", 0, True)`,
    'If exitCode = 0 Then',
    `  shell.Run "${vbsString(launchCommand)}", 0, False`,
    '  On Error Resume Next',
    '  fso.DeleteFile WScript.ScriptFullName, True',
    'End If',
    '',
  ].join('\r\n');

  fs.writeFileSync(updaterPath, script, 'utf8');
  const child = spawn('wscript.exe', ['//B', '//Nologo', updaterPath], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
  });
  child.unref();
}

function compareVersions(v1, v2) {
  const parts1 = String(v1).split('.').map(Number);
  const parts2 = String(v2).split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

// FIX: follows HTTP 301/302/307/308 redirects (required for GitHub release URLs)
function downloadFile(url, destPath, expectedChecksum) {
  return new Promise((resolve, reject) => {
    const doRequest = (targetUrl) => {
      https.get(targetUrl, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode)) {
          res.resume();
          const location = res.headers.location;
          if (!location) return reject(new Error('Redirect with no Location header'));
          return doRequest(location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error('Failed to download, status: ' + res.statusCode));
        }

        const file = fs.createWriteStream(destPath);
        const hash = crypto.createHash('sha256');

        res.on('data', chunk => hash.update(chunk));
        res.pipe(file);

        file.on('finish', () => {
          file.close();
          const fileHash = hash.digest('hex');
          if (fileHash !== expectedChecksum) {
            fs.unlink(destPath, () => {});
            reject(new Error('Checksum mismatch'));
          } else {
            resolve();
          }
        });
        file.on('error', err => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
      }).on('error', err => {
        try { fs.unlinkSync(destPath); } catch {}
        reject(err);
      });
    };
    doRequest(url);
  });
}

async function checkForUpdates(name) {
  try {
    log('Checking for updates...');
    const manifest = await fetchJSON(MANIFEST_URL);
    if (compareVersions(manifest.latestVersion, VERSION) <= 0) {
      log('No update found. Running current version.');
      return false;
    }

    log(`Update found: ${manifest.latestVersion}. Downloading...`);

    // Support both legacy flat manifest and new multi-platform manifest
    const platformKeys = manifestPlatformKeys();
    const platformInfo = manifest.platforms
      ? platformKeys.map(key => manifest.platforms[key]).find(Boolean)
      : manifest;
    if (!platformInfo || !platformInfo.downloadUrl) {
      log(`No update available for platform: ${platformKeys[0]}`);
      return false;
    }

    const ext = IS_WIN ? '.exe' : '';
    const tempBinPath = path.join(os.tmpdir(), `ClaudeUsageUploader_new${ext}`);

    if (fs.existsSync(tempBinPath)) {
      try { fs.unlinkSync(tempBinPath); } catch {}
    }

    await downloadFile(platformInfo.downloadUrl, tempBinPath, platformInfo.checksum);

    if (IS_WIN) {
      launchSilentWindowsUpdater(tempBinPath, manifest.latestVersion);
    } else {
      const shScriptPath = path.join(os.tmpdir(), `claude-uploader-update-${process.pid}.sh`);
      const targetBinPath = path.join(EXE_DIR, releaseBinaryName(manifest.latestVersion));
      const shContent = [
        '#!/bin/sh',
        'sleep 5',
        `mv -f "${tempBinPath}" "${targetBinPath}"`,
        `chmod +x "${targetBinPath}"`,
        `"${targetBinPath}" "--updated-from=${VERSION}" >/dev/null 2>&1 &`,
        'rm -- "$0"',
        '',
      ].join('\n');
      fs.writeFileSync(shScriptPath, shContent);
      fs.chmodSync(shScriptPath, '755');

      const child = spawn('sh', [shScriptPath], { detached: true, stdio: 'ignore' });
      child.unref();
    }

    log('Update downloaded and verified. Launching side-by-side updater and exiting.');
    return true;
  } catch (e) {
    log(`Update check failed: ${e.message}`);
    return false;
  }
}

// -------------------- ADMIN TRIGGER CHECK --------------------
// Polls GAS for a pending admin trigger. Returns { type: 'NONE'|'FORCE_RUN'|'PING' }.
function checkForAdminTrigger(name) {
  return new Promise((resolve) => {
    const MAX_REDIRECTS = 5;
    const none = { type: 'NONE' };

    const doRequest = (targetUrl, redirectsLeft) => {
      if (redirectsLeft <= 0) { log('Admin trigger check: too many redirects'); return resolve(none); }

      let parsedUrl;
      try { parsedUrl = new URL(targetUrl); } catch { return resolve(none); }

      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        timeout: 10000,
      };

      const req = https.request(options, res => {
        if ([301, 302, 307, 308].includes(res.statusCode)) {
          res.resume();
          if (res.headers.location) return doRequest(res.headers.location, redirectsLeft - 1);
          return resolve(none);
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            const extra = {
              paused: result.paused || false,
              uploadFrequency: result.uploadFrequency || 'weekly',
              uploadSchedule: result.uploadSchedule || {
                frequency: result.uploadFrequency || 'weekly',
                time: '13:00',
                day: 'Tuesday',
                timeZone: 'Asia/Kolkata'
              }
            };
            if (result.triggered === true) {
              const type = result.type || 'FORCE_RUN';
              log(`Admin trigger found for ${name} — type=${type}`);
              resolve({ type, ...extra });
            } else {
              resolve({ ...none, ...extra });
            }
          } catch {
            resolve(none);
          }
        });
      });

      req.on('error', () => { log('Admin trigger check failed (network)'); resolve(none); });
      req.on('timeout', () => { req.destroy(); log('Admin trigger check timed out'); resolve(none); });
      req.end();
    };

    const urlObj = new URL(WEBHOOK_URL);
    urlObj.searchParams.set('action', 'checkTrigger');
    urlObj.searchParams.set('name', name);
    doRequest(urlObj.toString(), MAX_REDIRECTS);
  });
}

// -------------------- VALIDATION --------------------
function validateSetup() {
  if (!fs.existsSync(GOOGLE_KEY_FILE)) {
    throw new Error(`${ERR.AUTH_KEY_MISSING}: Missing Google service account key: ${GOOGLE_KEY_FILE}`);
  }
}

// -------------------- NODE DISCOVERY --------------------
function findNode() {
  if (IS_WIN) {
    try {
      const out = execSync('where node', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (out) {
        const first = out.split(/\r?\n/)[0].trim();
        if (fs.existsSync(first)) return path.dirname(first);
      }
    } catch {}

    const fallbacks = [
      'C:\\Program Files\\nodejs',
      'C:\\Program Files (x86)\\nodejs',
      path.join(process.env.USERPROFILE || '', 'AppData', 'Roaming', 'npm'),
    ];
    for (const dir of fallbacks) {
      if (dir && fs.existsSync(path.join(dir, 'node.exe'))) return dir;
    }

    throw new Error('Cannot locate Node.js');
  }

  // macOS / Linux
  try {
    const out = execSync('which node', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (out && fs.existsSync(out)) return path.dirname(out);
  } catch {}

  const fallbacks = [
    '/usr/local/bin',
    '/usr/bin',
    '/opt/homebrew/bin',
    '/opt/homebrew/opt/node/bin',
    path.join(os.homedir(), '.nvm', 'versions', 'node', 'current', 'bin'),
    path.join(os.homedir(), '.volta', 'bin'),
    path.join(os.homedir(), '.fnm', 'current', 'bin'),
  ];
  for (const dir of fallbacks) {
    if (dir && fs.existsSync(path.join(dir, 'node'))) return dir;
  }

  throw new Error('Cannot locate Node.js. Install it from https://nodejs.org');
}

// -------------------- NODE / NPM HELPERS --------------------
function getNodeCmd() {
  if (!globalNodeDir) return 'node';
  return IS_WIN
    ? `"${path.join(globalNodeDir, 'node.exe')}"`
    : `"${path.join(globalNodeDir, 'node')}"`;
}

function getNpmCmd() {
  if (IS_WIN) {
    if (globalNodeDir) {
      // Use node npm-cli.js directly — avoids Sophos blocking .cmd files spawned from Node
      const npmCli = path.join(globalNodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js');
      if (fs.existsSync(npmCli)) return `${getNodeCmd()} "${npmCli}"`;
      return `"${path.join(globalNodeDir, 'npm.cmd')}"`;
    }
    return 'npm';
  }
  if (!globalNodeDir) return 'npm';
  return `"${path.join(globalNodeDir, 'npm')}"`;
}

function ensureNpm() {
  try {
    globalNodeDir = findNode();
    log(`Found Node.js at: ${globalNodeDir}`);
    run(`${getNodeCmd()} -v`);
    run(`${getNpmCmd()} -v`);
    log('Node & npm OK');
  } catch (e) {
    log(`Node/npm check failed: ${e.message}`);
    throw new Error('Node/npm not installed or not accessible');
  }
}

// -------------------- NAME --------------------
function sanitize(name) {
  return name.trim().replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_\-]/g, '');
}

// -------------------- CONFIG --------------------
function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    log('Invalid config');
    return null;
  }
}

function saveConfig(name) {
  if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ name: sanitize(name) }));
}

// -------------------- PROMPT --------------------
function askQuestion(prompt, validate) {
  return new Promise(res => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = () => {
      rl.question(prompt, ans => {
        if (!validate || validate(ans.trim())) { rl.close(); res(ans.trim()); }
        else ask();
      });
    };
    ask();
  });
}

function askName() {
  return askQuestion('Enter your full name (e.g. Nishant Jha): ', v => {
    if (v) return true;
    console.log('Name cannot be empty. Try again.');
    return false;
  });
}


// -------------------- SETUP GUI --------------------
function runSetupGui() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(SETUP_HTML);
        return;
      }
      if (req.method === 'POST' && req.url === '/setup') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const data = JSON.parse(body);
            const firstName = (data.firstName || '').trim();
            const lastName  = (data.lastName  || '').trim();
            if (!firstName || !lastName) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing name fields' }));
              return;
            }
            // Task registration happens after saveConfig() in main(). Starting
            // it here races a scheduled copy against the first-run process while
            // config.json does not exist yet, which can open a second setup UI.
            const taskOk = true;
            const taskError = '';
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ taskOk, taskError }));
            if (taskOk) {
              server.close();
              resolve({ firstName, lastName });
            }
          } catch (e) {
            res.writeHead(400); res.end('Parse error');
          }
        });
        return;
      }
      res.writeHead(404); res.end();
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const url = `http://127.0.0.1:${port}`;
      log(`Setup GUI listening at ${url}`);
      console.log(`\n  Setup wizard: ${url}\n  Opening in your browser...`);
      try {
        if (IS_WIN) {
          spawn('cmd.exe', ['/c', `start ${url}`], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
        } else if (IS_MAC) {
          spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
        } else {
          spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
        }
      } catch (_) {
        console.log(`  Could not auto-open. Please visit: ${url}`);
      }
      console.log('  Complete the form in your browser, then come back here.\n');
    });

    server.on('error', reject);
  });
}

// -------------------- SCHEDULING --------------------
function setupTask() {
  if (IS_WIN)   return setupTaskWindows();
  if (IS_MAC)   return setupTaskMac();
  return setupTaskLinux();
}

function xmlEsc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function setupTaskWindows() {
  const task = 'ClaudeUsageUploader';
  const healthTask = 'ClaudeUsageUploaderHealth';
  try {
    execSync(`schtasks /delete /tn "${task}" /f`, { stdio: 'ignore' });
    log('Removed existing scheduled task');
  } catch {}
  try { execSync(`schtasks /delete /tn "${healthTask}" /f`, { stdio: 'ignore' }); } catch {}

  const exePath = process.execPath;
  const launcherBatPath = path.join(EXE_DIR, 'launcher.bat');
  const launcherVbsPath = path.join(EXE_DIR, 'launcher.vbs');

  // Neutralize legacy restart loops. Old asynchronous launcher.bat processes
  // reread this file on their next iteration and then terminate.
  fs.writeFileSync(
    launcherBatPath,
    '@echo off\r\nexit /b 0\r\n'
  );
  log(`Legacy launcher loop neutralized: ${launcherBatPath}`);

  // The VBS waits for the worker and returns its exit code to Task Scheduler.
  // This gives Task Scheduler a real failure signal without a permanent batch loop.
  const vbsContent =
    `Option Explicit\r\n` +
    `Dim WshShell, exitCode\r\n` +
    `Set WshShell = CreateObject("WScript.Shell")\r\n` +
    `exitCode = WshShell.Run("""${exePath}"" --scheduled", 0, True)\r\n` +
    `WScript.Quit exitCode\r\n`;
  fs.writeFileSync(launcherVbsPath, vbsContent);
  log(`Launcher vbs created: ${launcherVbsPath}`);

  const healthVbsPath = path.join(EXE_DIR, 'healthcheck.vbs');
  const healthContent = [
    'Option Explicit',
    'Dim shell, fso, ageSeconds, pid, lockFile, heartbeatFile, taskName',
    'Set shell = CreateObject("WScript.Shell")',
    'Set fso = CreateObject("Scripting.FileSystemObject")',
    `lockFile = "${vbsString(path.join(CONFIG_DIR, 'service.lock'))}"`,
    `heartbeatFile = "${vbsString(HEALTH_FILE)}"`,
    `taskName = "${task}"`,
    'If Not fso.FileExists(heartbeatFile) Then',
    '  shell.Run "schtasks.exe /run /tn """ & taskName & """", 0, True',
    '  WScript.Quit 0',
    'End If',
    'ageSeconds = DateDiff("s", fso.GetFile(heartbeatFile).DateLastModified, Now)',
    'If ageSeconds > 1200 Then',
    '  If fso.FileExists(lockFile) Then',
    '    pid = Trim(fso.OpenTextFile(lockFile, 1).ReadAll)',
    '    If IsNumeric(pid) Then shell.Run "taskkill.exe /PID " & pid & " /F", 0, True',
    '  End If',
    '  WScript.Sleep 3000',
    '  shell.Run "schtasks.exe /run /tn """ & taskName & """", 0, True',
    'End If',
    '',
  ].join('\r\n');
  fs.writeFileSync(healthVbsPath, healthContent, 'utf8');

  // Task XML: ExecutionTimeLimit=PT0S (run indefinitely), Hidden=true, calls wscript.exe
  // on the VBS — which launches the bat hidden — which launches the exe hidden — which
  // runs the service loop. Visible to nobody. Manageable from Task Scheduler if needed.
  const taskXml = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Claude Usage Uploader — hidden background service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT2M</Delay>
    </LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>"${xmlEsc(launcherVbsPath)}"</Arguments>
    </Exec>
  </Actions>
</Task>`;

  const xmlPath = path.join(os.tmpdir(), 'claude-task.xml');
  fs.writeFileSync(xmlPath, Buffer.from('\ufeff' + taskXml, 'utf16le'));
  try {
    run(`schtasks /create /tn "${task}" /xml "${xmlPath}" /f`);
    log('Windows scheduled task created (single hidden supervised worker)');
  } finally {
    try { fs.unlinkSync(xmlPath); } catch {}
  }

  const healthXml = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Claude Usage Uploader external health monitor</Description></RegistrationInfo>
  <Triggers><TimeTrigger><Repetition><Interval>PT10M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>wscript.exe</Command><Arguments>"${xmlEsc(healthVbsPath)}"</Arguments></Exec></Actions>
</Task>`;
  const healthXmlPath = path.join(os.tmpdir(), 'claude-health-task.xml');
  fs.writeFileSync(healthXmlPath, Buffer.from('\ufeff' + healthXml, 'utf16le'));
  try {
    run(`schtasks /create /tn "${healthTask}" /xml "${healthXmlPath}" /f`);
    log('Windows external health monitor created');
  } finally {
    try { fs.unlinkSync(healthXmlPath); } catch {}
  }

  // Start the task immediately so the developer doesn't have to reboot/log out
  try {
    execSync(`schtasks /run /tn "${task}"`, { stdio: 'ignore' });
    log('Scheduled task started');
  } catch (e) {
    log(`Could not auto-start task: ${e.message} (will start on next login)`);
  }
}

function setupTaskMac() {
  const label = 'com.sigmasolve.claudeusageuploader';
  const plistDir = path.join(os.homedir(), 'Library', 'LaunchAgents');
  const plistPath = path.join(plistDir, `${label}.plist`);

  if (!fs.existsSync(plistDir)) fs.mkdirSync(plistDir, { recursive: true });

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${process.execPath}</string>
        <string>--scheduled</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>${LOG_FILE}</string>
</dict>
</plist>`;

  fs.writeFileSync(plistPath, plist);

  try { run(`launchctl unload "${plistPath}"`); } catch {}
  run(`launchctl load "${plistPath}"`);
  log(`macOS LaunchAgent installed: ${plistPath}`);
}

function setupTaskLinux() {
  const bin = process.execPath;
  // Service loop handles all scheduling internally — just need a single @reboot entry.
  // 2-minute delay gives the network time to come up before the first poll.
  const bootLine = `@reboot sleep 120 && "${bin}" --scheduled # ClaudeUsageUploader`;
  const cronLine = `*/15 * * * * pgrep -f "ClaudeUsageUploader" >/dev/null || "${bin}" --scheduled # ClaudeUsageUploader`;

  let currentCrontab = '';
  try { currentCrontab = run('crontab -l'); } catch {}

  const cleaned = currentCrontab
    .split('\n')
    .filter(l => !l.includes('ClaudeUsageUploader'))
    .join('\n')
    .trimEnd();

  const newCrontab = (cleaned ? cleaned + '\n' : '') + bootLine + '\n' + cronLine + '\n';

  const tmpFile = path.join(os.tmpdir(), 'claude-crontab.txt');
  fs.writeFileSync(tmpFile, newCrontab);
  run(`crontab "${tmpFile}"`);
  try { fs.unlinkSync(tmpFile); } catch {}

  log('Linux crontab entries added (@reboot + 15-minute watchdog)');
}

// -------------------- WEEK TRACKING --------------------
// ISO 8601 UTC week key ('YYYY-Www') — immune to DST and clock-skew.
// Thursday of each week pins the year (ISO rule): week 1 contains Jan 4th.
function isoWeekKey(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

function currentWeekKey() { return isoWeekKey(new Date()); }

const WEEKDAY_INDEX = { Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3, Thursday: 4, Friday: 5, Saturday: 6 };

function zonedDateParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: timeZone || 'Asia/Kolkata',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    weekday: 'long'
  }).formatToParts(date).reduce((out, part) => {
    if (part.type !== 'literal') out[part.type] = part.value;
    return out;
  }, {});
  return {
    year: Number(parts.year), month: Number(parts.month), day: Number(parts.day),
    hour: Number(parts.hour), minute: Number(parts.minute), weekday: parts.weekday
  };
}

function uploadPeriodKey(now, schedule) {
  schedule = schedule || {};
  const frequency = schedule.frequency || 'weekly';
  const p = zonedDateParts(now, schedule.timeZone);
  const match = /^(\d{1,2}):(\d{2})$/.exec(schedule.time || '13:00');
  const targetMinutes = match ? Number(match[1]) * 60 + Number(match[2]) : 13 * 60;
  const beforeTime = p.hour * 60 + p.minute < targetMinutes;
  const localAnchor = new Date(Date.UTC(p.year, p.month - 1, p.day, 12));

  if (frequency === 'daily') {
    if (beforeTime) localAnchor.setUTCDate(localAnchor.getUTCDate() - 1);
    return `daily:${localAnchor.toISOString().slice(0, 10)}`;
  }

  if (frequency === 'monthly') {
    const requestedDay = Math.max(1, Math.min(31, Number(schedule.monthDay) || 1));
    const lastDay = new Date(Date.UTC(p.year, p.month, 0)).getUTCDate();
    const targetDay = Math.min(requestedDay, lastDay);
    if (p.day < targetDay || (p.day === targetDay && beforeTime)) {
      localAnchor.setUTCMonth(localAnchor.getUTCMonth() - 1, 1);
    }
    return `monthly:${localAnchor.getUTCFullYear()}-${String(localAnchor.getUTCMonth() + 1).padStart(2, '0')}`;
  }

  const targetWeekday = WEEKDAY_INDEX[schedule.day] ?? WEEKDAY_INDEX.Tuesday;
  const currentWeekday = WEEKDAY_INDEX[p.weekday];
  let daysSinceTarget = (currentWeekday - targetWeekday + 7) % 7;
  if (daysSinceTarget === 0 && beforeTime) daysSinceTarget = 7;
  localAnchor.setUTCDate(localAnchor.getUTCDate() - daysSinceTarget);
  return `weekly:${localAnchor.toISOString().slice(0, 10)}`;
}

function isUploadDue(cfg, schedule, now = new Date()) {
  const currentKey = uploadPeriodKey(now, schedule);
  if (cfg.lastUploadPeriodKey) return cfg.lastUploadPeriodKey !== currentKey;

  // Legacy weekly keys can be migrated without causing a duplicate upload.
  const frequency = (schedule && schedule.frequency) || 'weekly';
  const stored = cfg.lastSuccessfulUploadAt || cfg.lastUploadDate || cfg.lastUploadWeek;
  if (!stored) return true;
  if (frequency === 'weekly' && /^\d{4}-W\d{2}$/.test(stored)) {
    return stored !== currentWeekKey();
  }
  const parsed = new Date(stored);
  if (Number.isNaN(parsed.getTime())) return true;
  return uploadPeriodKey(parsed, schedule) !== currentKey;
}

function saveUploadDate(cfg, schedule) {
  const now = new Date();
  const periodKey = uploadPeriodKey(now, schedule);
  const updated = {
    ...cfg,
    lastSuccessfulUploadAt: now.toISOString(),
    lastUploadPeriodKey: periodKey,
    lastUploadFrequency: (schedule && schedule.frequency) || 'weekly',
    // Retain legacy fields for rollback compatibility only.
    lastUploadWeek: currentWeekKey(),
    lastUploadDate: now.toISOString()
  };
  // Atomic write — safe if the process is killed mid-write
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(updated));
  fs.renameSync(tmp, CONFIG_FILE);
}

// -------------------- OFFLINE RETRY QUEUE --------------------
function loadRetryQueue() {
  try {
    if (fs.existsSync(RETRY_QUEUE_FILE)) {
      return JSON.parse(fs.readFileSync(RETRY_QUEUE_FILE, 'utf8'));
    }
  } catch { log('Failed to load retry queue'); }
  return [];
}

function saveRetryQueue(queue) {
  try {
    fs.writeFileSync(RETRY_QUEUE_FILE, JSON.stringify(queue, null, 2));
  } catch (e) { log(`Failed to save retry queue: ${e.message}`); }
}

function enqueueFailedUpload(name, source, sessionData, dailyData, error) {
  const queue = loadRetryQueue();
  if (queue.length >= 20) {
    log('Retry queue full (20 items) — dropping oldest entry');
    queue.shift();
  }
  queue.push({
    id: `q_${Date.now()}`,
    name,
    source,
    queuedAt: new Date().toISOString(),
    retryCount: 0,
    nextRetryAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    sessionData,
    dailyData,
    lastError: error
  });
  saveRetryQueue(queue);
  log(`Enqueued failed upload for retry (queue size: ${queue.length})`);
}

function getRetryDelay(retryCount) {
  const baseMs = 5 * 60 * 1000;
  const delay = baseMs * Math.pow(3, retryCount);
  return Math.min(delay, 6 * 60 * 60 * 1000);
}

// -------------------- CCUSAGE --------------------
function ensureCCUsage() {
  const vendorPlatform = IS_WIN
    ? 'win32-x64'
    : IS_MAC
      ? (process.arch === 'arm64' ? 'darwin-arm64' : 'darwin-x64')
      : 'linux-x64';
  const vendorFile = IS_WIN ? 'ccusage.exe' : 'ccusage';
  const packagedVendor = path.join(__dirname, 'vendor', vendorPlatform, vendorFile);
  const extractedDir = path.join(CONFIG_DIR, 'tools', `ccusage-${vendorPlatform}`);
  const extractedVendor = path.join(extractedDir, vendorFile);

  if (!fs.existsSync(extractedVendor) && fs.existsSync(packagedVendor)) {
    if (!fs.existsSync(extractedDir)) fs.mkdirSync(extractedDir, { recursive: true });
    fs.copyFileSync(packagedVendor, extractedVendor);
    if (!IS_WIN) fs.chmodSync(extractedVendor, '755');
    log(`Extracted bundled ccusage tool: ${extractedVendor}`);
  }
  if (fs.existsSync(extractedVendor)) {
    globalCcusageBinPath = extractedVendor;
    log(`ccusage OK (self-contained): ${extractedVendor}`);
    return;
  }

  const bundledNames = IS_WIN
    ? ['ccusage.exe', path.join('tools', 'ccusage.exe')]
    : ['ccusage', path.join('tools', 'ccusage')];
  for (const name of bundledNames) {
    const candidate = path.join(EXE_DIR, name);
    if (fs.existsSync(candidate)) {
      globalCcusageBinPath = candidate;
      log(`ccusage OK (bundled native tool): ${candidate}`);
      return;
    }
  }

  if (process.pkg) {
    throw new Error(`${ERR.CCUSAGE_NOT_FOUND}: packaged ccusage tool is missing or was quarantined by endpoint security`);
  }

  // Development/backward-compatibility fallback only. Production v2.0.4
  // packages include the native tool and never install npm packages at runtime.
  ensureNpm();
  const envOpts = globalNodeDir
    ? { env: { ...process.env, PATH: `${globalNodeDir}${path.delimiter}${process.env.PATH}` } }
    : {};

  const resolveCcusageJs = (baseDir) => {
    const paths = [
      path.join(baseDir, 'dist', 'cli.js'),
      path.join(baseDir, 'dist', 'index.js')
    ];
    for (const p of paths) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  };

  // --- STRATEGY 1: Check local install in CONFIG_DIR (no admin rights needed) ---
  const localCcusageDir = path.join(CONFIG_DIR, 'node_modules', 'ccusage');
  const localCcusageJs = resolveCcusageJs(localCcusageDir);
  if (localCcusageJs) {
    globalCcusageJsPath = localCcusageJs;
    log(`ccusage OK (local): ${localCcusageJs}`);
    return;
  }

  // --- STRATEGY 2: Try global ccusage in PATH ---
  try {
    run('ccusage --help', envOpts);
    log('ccusage OK (global PATH)');
    // Try to resolve the JS entry point to run via node directly (bypasses shell wrapping and PATH issues under launchd/cron)
    try {
      const npmRoot = execSync('npm root -g', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      const jsPath = resolveCcusageJs(path.join(npmRoot, 'ccusage'));
      if (jsPath) {
        globalCcusageJsPath = jsPath;
        log(`Stealth mode: using ccusage entry point at ${jsPath}`);
      }
    } catch (e) {
      log(`Could not resolve global stealth path: ${e.message}`);
    }
    return;
  } catch {
    log('ccusage not found globally, will install locally...');
  }

  // --- STRATEGY 3: Install locally into CONFIG_DIR (no sudo / admin needed) ---
  try {
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    log(`Installing ccusage locally into ${CONFIG_DIR} ...`);
    const npmPrefix = `--prefix "${CONFIG_DIR}"`;
    run(`${getNpmCmd()} install ${npmPrefix} ccusage`, envOpts);
    const postInstallJs = resolveCcusageJs(localCcusageDir);
    if (postInstallJs) {
      globalCcusageJsPath = postInstallJs;
      log(`ccusage installed locally: ${postInstallJs}`);
      return;
    }
    throw new Error('Local install succeeded but entry point not found at expected path');
  } catch (localErr) {
    log(`Local install failed: ${localErr.message}`);
    // --- STRATEGY 4: Last-resort global install (may need admin rights) ---
    try {
      log('Attempting global install as last resort...');
      run(`${getNpmCmd()} install -g ccusage`, envOpts);
      log('ccusage installed globally');
    } catch (globalErr) {
      throw new Error(
        `ccusage setup failed. Local error: ${localErr.message}. Global error: ${globalErr.message}. ` +
        `Try running: npm install --prefix "${CONFIG_DIR}" ccusage`
      );
    }
  }
}

// -------------------- REPORT --------------------
async function generateReports() {
  const sessionFile = path.join(os.tmpdir(), 'session.json');
  const dailyFile   = path.join(os.tmpdir(), 'daily.json');

  const envOpts = globalNodeDir
    ? { env: { ...process.env, PATH: `${globalNodeDir}${path.delimiter}${process.env.PATH}` } }
    : {};

  if (globalCcusageBinPath) {
    await runCcusage(`"${globalCcusageBinPath}" session --json`, sessionFile, envOpts);
    await runCcusage(`"${globalCcusageBinPath}" daily --json`,   dailyFile,   envOpts);
  } else if (globalCcusageJsPath) {
    await runCcusage(`${getNodeCmd()} "${globalCcusageJsPath}" session --json`, sessionFile, envOpts);
    await runCcusage(`${getNodeCmd()} "${globalCcusageJsPath}" daily --json`,   dailyFile,   envOpts);
  } else {
    await runCcusage('ccusage session --json', sessionFile, envOpts);
    await runCcusage('ccusage daily --json',   dailyFile,   envOpts);
  }

  if (fs.statSync(sessionFile).size === 0 || fs.statSync(dailyFile).size === 0) {
    throw new Error(`${ERR.CCUSAGE_EMPTY_OUTPUT}: Report generation produced empty files`);
  }

  try {
    JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
    JSON.parse(fs.readFileSync(dailyFile,   'utf8'));
  } catch {
    throw new Error(`${ERR.CCUSAGE_INVALID_JSON}: Report files contain invalid JSON`);
  }

  log('Reports generated and validated');
  return { sessionFile, dailyFile };
}

// -------------------- DRIVE AUTH (raw JWT, no googleapis) --------------------
// Uses raw HTTPS to avoid the 'Invalid host defined options' error that occurs
// when googleapis tries to configure its http agent inside a pkg-compiled binary.
async function getDriveAccessToken() {
  const key = JSON.parse(fs.readFileSync(GOOGLE_KEY_FILE, 'utf8'));
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const claim  = Buffer.from(JSON.stringify({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/drive.file',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  })).toString('base64url');
  const sigInput = `${header}.${claim}`;
  const sig = crypto.createSign('RSA-SHA256').update(sigInput).sign(key.private_key, 'base64url');
  const jwt = `${sigInput}.${sig}`;

  const res = await nodeFetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Drive auth failed: ' + JSON.stringify(data));
  log('Drive auth token obtained');
  return data.access_token;
}

// -------------------- DRIVE PRE-CHECK --------------------
async function validateDrive() {
  const token = await getDriveAccessToken();
  const res = await nodeFetch(
    `https://www.googleapis.com/drive/v3/files?pageSize=1&fields=files(id)&supportsAllDrives=true&includeItemsFromAllDrives=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error(`Drive list failed: ${res.status} ${await res.text()}`);
  log('Drive authentication OK');
}

// -------------------- DRIVE UPLOAD (raw multipart) --------------------
async function upload(name, sessionFile, dailyFile) {
  const token = await getDriveAccessToken();

  async function findFileId(fileName) {
    const q = encodeURIComponent(`name='${fileName}' and '${getDriveFolderId()}' in parents and trashed=false`);
    const res = await nodeFetch(
      `https://www.googleapis.com/drive/v3/files?q=${q}&corpora=allDrives&includeItemsFromAllDrives=true&supportsAllDrives=true&fields=files(id)`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await res.json();
    return (data.files && data.files[0]) ? data.files[0].id : null;
  }

  async function verifyFileInFolder(fileId, fileName) {
    const res = await nodeFetch(
      `https://www.googleapis.com/drive/v3/files/${fileId}?fields=id,parents&supportsAllDrives=true&includeItemsFromAllDrives=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok) throw new Error(`${ERR.DRIVE_VERIFY_FAILED}: files.get ${res.status} for ${fileName}`);
    const data = await res.json();
    if (!data.parents || !data.parents.includes(getDriveFolderId())) {
      throw new Error(`${ERR.DRIVE_VERIFY_FAILED}: ${fileName} (${fileId}) not in expected folder ${getDriveFolderId()}`);
    }
    log(`Verified ${fileName} (${fileId}) in Drive folder`);
    return fileId;
  }

  async function uploadOrUpdateFile(filePath, fileName) {
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const existingId = await findFileId(fileName);
        const fileContent = fs.readFileSync(filePath);
        const boundary = '-------314159265358979323846';
        const delimiter = `\r\n--${boundary}\r\n`;
        const closeDelimiter = `\r\n--${boundary}--`;

        const metadataObj = { name: fileName };
        if (!existingId) {
            // Only set parents when creating a new file
            metadataObj.parents = [getDriveFolderId()];
        }
        const metadata = JSON.stringify(metadataObj);

        const body = Buffer.concat([
          Buffer.from(
            `--${boundary}\r\n` +
            'Content-Type: application/json; charset=UTF-8\r\n\r\n' +
            metadata +
            delimiter +
            'Content-Type: application/json\r\n\r\n'
          ),
          fileContent,
          Buffer.from(closeDelimiter),
        ]);

        const url = existingId
          ? `https://www.googleapis.com/upload/drive/v3/files/${existingId}?uploadType=multipart&supportsAllDrives=true&fields=id`
          : `https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id`;

        const method = existingId ? 'PATCH' : 'POST';

        const res = await nodeFetch(url, {
            method: method,
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': `multipart/related; boundary="${boundary}"`,
              'Content-Length': body.length,
            },
            body,
        });

        const data = await res.json();
        if (!data.id) {
          const errStr = JSON.stringify(data);
          let code = ERR.DRIVE_UPLOAD_FAILED;
          if (errStr.includes('storageQuotaExceeded')) code = ERR.DRIVE_QUOTA_EXCEEDED;
          if (res.status === 429) code = ERR.DRIVE_RATE_LIMITED;
          throw new Error(`${code}: ${errStr}`);
        }
        log(existingId ? `Replaced existing file ${fileName} → ${data.id}` : `Created new file ${fileName} → ${data.id}`);
        await verifyFileInFolder(data.id, fileName);
        return data.id;
      } catch (e) {
        log(`Upload attempt ${attempt} failed for ${fileName}: ${e.message}`);
        // v2.0.7: a server-configured folder that we cannot see or write to would
        // otherwise fail every attempt forever, silently. Detect that specific
        // class of failure and drop back to the compiled default so the remaining
        // retries land somewhere real — reporting degrades, it does not stop.
        if (/notFound|File not found|insufficientFilePermissions|insufficientPermissions|403|404/i.test(e.message)) {
          if (revertDriveFolderToDefault(`upload to ${activeDriveFolderId} failed: ${e.message.slice(0, 120)}`)) {
            continue; // retry immediately against the default folder
          }
        }
        if (attempt === MAX_RETRIES) throw e;
        await new Promise(r => setTimeout(r, 2000 * attempt));
      }
    }
  }

  const sanitizedFirst = sanitize(name.split('_')[0] || name);
  const sanitizedLast  = sanitize(name.split('_').slice(1).join('_') || '');
  const sessionName = sanitizedLast
    ? `${sanitizedFirst}_${sanitizedLast}_claude_session.json`
    : `${sanitizedFirst}_claude_session.json`;
  const dailyName = sanitizedLast
    ? `${sanitizedFirst}_${sanitizedLast}_claude_daily.json`
    : `${sanitizedFirst}_claude_daily.json`;

  log(`Phase 1: Uploading session report (${sessionName})...`);
  let sessionFileId = null;
  try {
    sessionFileId = await uploadOrUpdateFile(sessionFile, sessionName);
  } catch (err) {
    log(`Warning: Session report upload failed: ${err.message}`);
  }

  log(`Phase 2: Uploading daily report (${dailyName})...`);
  let dailyFileId = null;
  try {
    dailyFileId = await uploadOrUpdateFile(dailyFile, dailyName);
  } catch (err) {
    log(`Warning: Daily report upload failed: ${err.message}`);
  }

  return { sessionFileId, dailyFileId };
}

// -------------------- WAIT FOR USER --------------------
function waitForEnter() {
  return new Promise(res => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('Press Enter to exit...', () => { rl.close(); res(); });
  });
}

// -------------------- GENERATE & UPLOAD --------------------
// Single function that runs the full generate→upload pipeline with granular status pings.
// source: 'admin' | 'scheduled' | 'force'
async function runGenerateAndUpload(cfg, source, uploadSchedule) {
  try {
    // --- Upload guard: re-verify pause state before doing any work ---
    try {
      const guardCheck = await checkForAdminTrigger(cfg.name);
      if (guardCheck.paused === true) {
        log(`Upload blocked \u2014 agent is paused (source=${source})`);
        await sendPing(cfg.name, 'PAUSED', `Upload skipped: paused (source=${source})`);
        return;
      }
    } catch (e) {
      log(`Pause guard check failed: ${e.message} \u2014 continuing with upload`);
    }

    await sendPing(cfg.name, 'POLLING_ACK', `Trigger received — starting pipeline`);
    log(`POLLING_ACK sent (${source})`);

    validateSetup();
    ensureCCUsage();

    await sendPing(cfg.name, 'GENERATE_START', `source=${source}`);
    log(`Generate start (${source})`);

    let sessionFile, dailyFile;
    try {
      ({ sessionFile, dailyFile } = await generateReports());
    } catch (e) {
      const msg = e.message || '';
      let code = ERR.CCUSAGE_FAILED;
      if (msg.startsWith(ERR.CCUSAGE_TIMEOUT))       code = ERR.CCUSAGE_TIMEOUT;
      else if (msg.startsWith(ERR.CCUSAGE_NOT_FOUND)) code = ERR.CCUSAGE_NOT_FOUND;
      else if (msg.startsWith(ERR.CCUSAGE_EMPTY_OUTPUT) || msg.startsWith(ERR.NO_DATA) || msg.includes('empty')) code = ERR.NO_DATA;
      else if (msg.startsWith(ERR.CCUSAGE_INVALID_JSON) || msg.includes('invalid JSON')) code = ERR.CCUSAGE_INVALID_JSON;
      await sendPing(cfg.name, 'FAILURE', `${code}: ${msg}`);
      log(`Generate failed [${code}]: ${msg}`);
      return;
    }

    let sessionCount = 0, dailyCount = 0;
    try {
      const s = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
      const d = JSON.parse(fs.readFileSync(dailyFile, 'utf8'));
      sessionCount = Array.isArray(s) ? s.length : Object.keys(s).length;
      dailyCount   = Array.isArray(d) ? d.length : Object.keys(d).length;
    } catch {}
    await sendPing(cfg.name, 'GENERATE_DONE', `sessions:${sessionCount} daily:${dailyCount}`);

    await sendPing(cfg.name, 'UPLOAD_START', 'Uploading to Drive');
    let uploadedFileIds = {};
    try {
      await validateDrive();
      uploadedFileIds = await upload(cfg.name, sessionFile, dailyFile);
    } catch (e) {
      const msg = e.message || '';
      let code = ERR.DRIVE_UPLOAD_FAILED;
      let shouldRetry = true;
      if (msg.includes('unauthorized_client') || msg.includes('invalid_grant')) { code = ERR.DRIVE_AUTH_FAILED; shouldRetry = false; }
      else if (msg.startsWith(ERR.DRIVE_QUOTA_EXCEEDED) || msg.includes('quota'))    { code = ERR.DRIVE_QUOTA_EXCEEDED; shouldRetry = false; }
      else if (msg.startsWith(ERR.DRIVE_RATE_LIMITED))                               { code = ERR.DRIVE_RATE_LIMITED; shouldRetry = true; }
      else if (msg.startsWith(ERR.AUTH_KEY_MISSING) || msg.includes('Missing Google') || msg.includes('service account')) { code = ERR.CREDENTIALS_MISSING; shouldRetry = false; }
      else if (msg.startsWith(ERR.DRIVE_VERIFY_FAILED))                              { code = ERR.DRIVE_VERIFY_FAILED; shouldRetry = false; }

      if (shouldRetry) {
        try {
          const sData = fs.readFileSync(sessionFile, 'utf8');
          const dData = fs.readFileSync(dailyFile, 'utf8');
          enqueueFailedUpload(cfg.name, source, sData, dData, msg);
          await sendPing(cfg.name, 'FAILURE', `${code}: ${msg} (queued for retry)`);
        } catch (qErr) {
          await sendPing(cfg.name, 'FAILURE', `${code}: ${msg} (queue failed: ${qErr.message})`);
        }
      } else {
        await sendPing(cfg.name, 'FAILURE', `${code}: ${e.message}`);
      }
      log(`Upload failed: ${msg}`);
      return;
    }
    await sendPing(cfg.name, 'UPLOAD_DONE', 'Files uploaded to Drive');

    const weekOf = currentWeekKey();

    let msg = '';
    if (source === 'admin')      msg = `Admin-triggered for week of ${weekOf}`;
    else if (source === 'force') msg = `Force-run for week of ${weekOf}`;
    else                          msg = `Scheduled upload for week of ${weekOf}`;

    const successResult = await sendPing(cfg.name, 'SUCCESS', msg, {
      sessionFileId: uploadedFileIds.sessionFileId || null,
      dailyFileId:   uploadedFileIds.dailyFileId   || null,
    });

    // Drive upload succeeded; commit lastUploadWeek if the SUCCESS ping was acked
    // OR durably queued for replay. Only skip commit when both ping and queue write failed.
    if (successResult.ok || successResult.queued) {
      saveUploadDate(cfg, uploadSchedule);
      log(`Upload complete (${source}) for week ${weekOf}; ack=${successResult.ok} queued=${successResult.queued}`);
    } else {
      log(`Upload complete (${source}) for week ${weekOf} BUT success-ping lost and queue-write failed; lastUploadWeek NOT committed`);
    }
  } catch (e) {
    log(`runGenerateAndUpload unexpected error: ${e.message}`);
    await sendPing(cfg.name, 'FAILURE', `${ERR.UNKNOWN_ERROR}: ${e.message}`);
  }
}

// -------------------- SINGLE-INSTANCE LOCK --------------------
// Ensures only one service-loop process runs at a time. Without this, if the user
// double-clicks the exe while the Task Scheduler instance is already running hidden,
// we'd get two pollers consuming the same triggers and double heartbeats.
const LOCK_FILE = path.join(CONFIG_DIR, 'service.lock');

function isPidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code === 'EPERM'; }  // EPERM = exists but signaling not allowed
}

function acquireSingleInstanceLock() {
  try {
    if (fs.existsSync(LOCK_FILE)) {
      const oldPid = parseInt(fs.readFileSync(LOCK_FILE, 'utf8').trim(), 10);
      if (isPidAlive(oldPid) && oldPid !== process.pid) {
        log(`Another service instance is running (pid=${oldPid}); exiting`);
        return false;
      }
      // stale lock — process is dead, take over
      try { fs.unlinkSync(LOCK_FILE); } catch {}
    }
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    // Atomic create prevents two scheduler/legacy-launcher processes from both
    // passing an exists() check and becoming active workers.
    const fd = fs.openSync(LOCK_FILE, 'wx');
    fs.writeFileSync(fd, String(process.pid));
    fs.closeSync(fd);
    const releaseLock = () => { try { fs.unlinkSync(LOCK_FILE); } catch {} };
    process.on('exit', releaseLock);
    process.on('SIGINT',  () => { releaseLock(); process.exit(0); });
    process.on('SIGTERM', () => { releaseLock(); process.exit(0); });
    return true;
  } catch (e) {
    if (e.code === 'EEXIST') {
      log('Another instance won the atomic service lock; exiting');
      return false;
    }
    log(`Lock acquisition error: ${e.message} (failing closed to prevent duplicate uploads)`);
    return false;
  }
}

function writeLocalHealth() {
  try {
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(HEALTH_FILE, new Date().toISOString(), 'utf8');
  } catch (e) {
    log(`Local health write failed: ${e.message}`);
  }
}

// -------------------- SERVICE LOOP --------------------
// The tool runs as a persistent background process. It never exits under normal conditions.
// - Polls GAS every 60s for admin triggers (PING or FORCE_RUN)
// - Sends a heartbeat every 5 minutes so the dashboard shows online status
// - Checks once per hour (plus per-machine jitter) if a scheduled upload is due
// - Checks once per hour for a new version
async function serviceLoop(cfg) {
  if (!acquireSingleInstanceLock()) {
    console.log('Claude Usage Uploader is already running in the background.');
    process.exit(0);
    return;
  }

  let isRunning = false;
  let isPausedState = false;
  let currentUploadSchedule = {
    frequency: 'weekly', time: '13:00', day: 'Tuesday', timeZone: 'Asia/Kolkata'
  };
  let lastHeartbeatSentAt = Date.now();

  // v2.0.7: restore the last server-assigned Drive folder before the first poll.
  // Without this, a restart would upload one round to the compiled default even
  // though the server had already moved the fleet elsewhere.
  if (cfg && cfg.driveFolderId) {
    applyServerDriveFolderId(cfg.driveFolderId, false); // already persisted
  }

  log(`Service loop started v${VERSION} — polling every ${POLL_INTERVAL_MS / 1000}s ` +
      `(pid=${process.pid}, driveFolder=${getDriveFolderId()})`);
  writeLocalHealth();

  // Independent local liveness signal consumed by the Windows health task.
  // It detects a blocked event loop even when remote heartbeat delivery fails.
  setInterval(writeLocalHealth, 60 * 1000);

  // Common extra fields for all pings
  const pingExtra = (overrides = {}) => ({
    version: VERSION,
    lastUpdateCheck: lastUpdateCheckAt || 'never',
    ...overrides
  });

  // Send immediate heartbeat on startup
  await sendPing(cfg.name, 'HEARTBEAT', `v${VERSION}`, pingExtra()).catch(() => {});
  lastHeartbeatSentAt = Date.now();

  // Handle --force immediately before entering the loop
  if (FORCE_RUN) {
    isRunning = true;
    await runGenerateAndUpload(cfg, 'force', currentUploadSchedule);
    cfg = loadConfig() || cfg;
    isRunning = false;
  }

  // --- Poll for admin triggers (PING / FORCE_RUN) ---
  setInterval(async () => {
    const nextPollAt = new Date(Date.now() + POLL_INTERVAL_MS).toISOString();

    if (isRunning) return;
    isRunning = true;
    try {
      const trigger = await checkForAdminTrigger(cfg.name);

      // --- Update upload frequency from server ---
      if (trigger.uploadSchedule) currentUploadSchedule = trigger.uploadSchedule;
      else if (trigger.uploadFrequency) currentUploadSchedule.frequency = trigger.uploadFrequency;

      // --- v2.0.7: update the Drive upload target from server ---
      // Validated and persisted inside applyServerDriveFolderId. A missing or
      // malformed value leaves the current folder untouched.
      applyServerDriveFolderId(trigger.driveFolderId);

      // --- Handle paused state transitions ---
      const serverPaused = trigger.paused === true;
      if (serverPaused && !isPausedState) {
        isPausedState = true;
        log('Agent PAUSED by admin');
        await sendPing(cfg.name, 'PAUSED', `v${VERSION} paused by admin`, pingExtra({ nextPollAt }));
      } else if (!serverPaused && isPausedState) {
        isPausedState = false;
        log('Agent RESUMED by admin');
        await sendPing(cfg.name, 'HEARTBEAT', `v${VERSION} resumed`, pingExtra({ nextPollAt }));
      }

      if (isPausedState) {
        // Idle while paused - no redundant pings
      } else if (trigger.type === 'PING') {
        await sendPing(cfg.name, 'PONG', `v${VERSION} online`, pingExtra({ nextPollAt }));
        log('PONG sent');
      } else if (trigger.type === 'FORCE_RUN') {
        await sendPing(cfg.name, 'POLLING_ACK', 'Trigger received — starting pipeline', pingExtra({ nextPollAt }));
        log('POLLING_ACK sent');
        const freshCfg = loadConfig() || cfg;
        await runGenerateAndUpload(freshCfg, 'admin', currentUploadSchedule);
        cfg = loadConfig() || cfg;
      } else if (trigger.type === 'UPDATE') {
        await sendPing(cfg.name, 'UPDATE_START', 'Checking for hot-patch update...', pingExtra({ nextPollAt }));
        log('Update trigger received. Checking for updates...');
        const isUpdating = await checkForUpdates(cfg.name);
        if (isUpdating) {
          log('Update applied — exiting for replacement by launcher');
          process.exit(0);
        }
      }
    } catch (e) {
      log(`Poll loop error: ${e.message}`);
    } finally {
      isRunning = false;
    }
  }, POLL_INTERVAL_MS);

  // --- Heartbeat every 5 minutes ---
  setInterval(async () => {
    try {
      const status = isPausedState ? 'PAUSED' : 'HEARTBEAT';
      await sendPing(cfg.name, status, `v${VERSION}`, pingExtra());
      lastHeartbeatSentAt = Date.now();
    } catch {}
  }, HEARTBEAT_INTERVAL_MS);

  // --- Watchdog: exit if heartbeat loop stalls for >10 min ---
  const WATCHDOG_INTERVAL_MS = 2 * 60 * 1000;
  const WATCHDOG_THRESHOLD_MS = 10 * 60 * 1000;
  setInterval(() => {
    const stalledMs = Date.now() - lastHeartbeatSentAt;
    if (stalledMs > WATCHDOG_THRESHOLD_MS) {
      log(`${ERR.WATCHDOG_STALL}: no heartbeat for ${Math.round(stalledMs / 60000)}min — restarting`);
      appendEvent({ kind: 'watchdog-stall', stalledMs });
      process.exit(1);
    }
  }, WATCHDOG_INTERVAL_MS);

  // --- Scheduled upload check every hour ---
  // Deterministic per-machine jitter (0-15 min, stable across restarts) staggers the
  // fleet so all clients don't hit Drive/GAS at the same top-of-hour tick.
  const uploadJitterMs = (crypto.createHash('sha256').update(String(cfg.name || os.hostname()))
    .digest().readUInt32BE(0) % (15 * 60)) * 1000;
  const uploadCheckTick = async () => {
    if (isRunning || isPausedState) return;
    isRunning = true;
    try {
      const freshCfg = loadConfig();
      if (freshCfg && isUploadDue(freshCfg, currentUploadSchedule)) {
        log(`Scheduled upload due (frequency=${currentUploadSchedule.frequency}, time=${currentUploadSchedule.time}) — starting`);
        await runGenerateAndUpload(freshCfg, 'scheduled', currentUploadSchedule);
        cfg = loadConfig() || cfg;
      }
    } catch (e) {
      log(`Upload check error: ${e.message}`);
    } finally {
      isRunning = false;
    }
  };
  setTimeout(() => {
    uploadCheckTick();
    setInterval(uploadCheckTick, UPLOAD_CHECK_MS);
  }, uploadJitterMs);

  // --- Retry queue processing every 5 minutes ---
  const RETRY_CHECK_MS = 5 * 60 * 1000;
  setInterval(async () => {
    if (isRunning || isPausedState) return;
    const queue = loadRetryQueue();
    if (queue.length === 0) return;

    const now = new Date();
    let updated = false;

    for (let i = 0; i < queue.length; i++) {
      const item = queue[i];
      if (new Date(item.nextRetryAt) > now) continue;

      log(`Retrying queued upload ${item.id} (attempt ${item.retryCount + 1})`);
      isRunning = true;
      try {
        const retrySessionFile = path.join(os.tmpdir(), `retry_session_${item.id}.json`);
        const retryDailyFile = path.join(os.tmpdir(), `retry_daily_${item.id}.json`);
        fs.writeFileSync(retrySessionFile, item.sessionData);
        fs.writeFileSync(retryDailyFile, item.dailyData);

        await validateDrive();
        await upload(item.name, retrySessionFile, retryDailyFile);

        queue.splice(i, 1);
        i--;
        updated = true;
        log(`Retry successful for ${item.id}`);
        await sendPing(item.name, 'SUCCESS', `Retry upload succeeded (queued at ${item.queuedAt})`, pingExtra());

        try { fs.unlinkSync(retrySessionFile); } catch {}
        try { fs.unlinkSync(retryDailyFile); } catch {}
      } catch (e) {
        item.retryCount++;
        if (item.retryCount >= 8) {
          log(`Retry ${item.id} permanently failed after ${item.retryCount} attempts`);
          await sendPing(item.name, 'FAILURE', `Retry gave up after ${item.retryCount} attempts: ${e.message}`, pingExtra());
          queue.splice(i, 1);
          i--;
        } else {
          item.nextRetryAt = new Date(Date.now() + getRetryDelay(item.retryCount)).toISOString();
          item.lastError = e.message;
          log(`Retry ${item.id} failed (attempt ${item.retryCount}), next at ${item.nextRetryAt}`);
        }
        updated = true;
      } finally {
        isRunning = false;
      }
    }

    if (updated) saveRetryQueue(queue);
  }, RETRY_CHECK_MS);

  // --- Update check every hour (startup also checks immediately) ---
  setInterval(async () => {
    // Never start (or exit for) an update while an upload/retry is in flight.
    if (isRunning) return;
    try {
      lastUpdateCheckAt = new Date().toISOString();
      const isUpdating = await checkForUpdates(cfg.name);
      if (isUpdating) {
        log('Update applied — exiting for replacement by launcher');
        setTimeout(() => process.exit(0), 3000);
      }
    } catch (e) {
      log(`Update check error: ${e.message}`);
    }
  }, UPDATE_CHECK_MS);

  // --- Replay failed pings every 5 minutes ---
  setInterval(async () => {
    const queue = loadFailedPings();
    if (queue.length === 0) return;
    const remaining = [];
    for (const item of queue) {
      try {
        const r = await sendPingOnce(item.payload);  // one shot per cycle, not full retry
        if (r.ok) {
          appendEvent({ kind: 'replay-success', id: item.id, name: item.payload.name, status: item.payload.status });
          log(`Ping replay succeeded: ${item.payload.name} ${item.payload.status}`);
        } else {
          remaining.push(item);
        }
      } catch { remaining.push(item); }
    }
    if (remaining.length !== queue.length) rewriteFailedPings(remaining);
  }, 5 * 60 * 1000);

  // Keep the Node.js event loop alive indefinitely
  process.stdin.resume();
}

// -------------------- MAIN --------------------
async function main() {
  // Setup mode — first run (no config file yet)
  if (!fs.existsSync(CONFIG_FILE)) {
    console.log('First-run setup...');
    try {
      validateSetup();
      const setupResult = await runSetupGui();
      const combinedName = `${setupResult.firstName}_${setupResult.lastName}`;
      saveConfig(combinedName);
      await sendPing(sanitize(combinedName), 'REGISTERED', 'Initial setup completed');
      setupTask();
      console.log('Setup complete! The uploader is now running in the background.');
    } catch (e) {
      log(`SETUP ERROR: ${e.message}`);
      console.error(`Setup failed: ${e.message}`);
      await waitForEnter();
      process.exit(1);
      return;
    }
    const cfg = loadConfig();
    if (!cfg) { process.exit(1); return; }
    await serviceLoop(cfg);
    return;
  }

  // Manual launches repair registration; scheduled workers must not delete and
  // recreate the task that is currently supervising them. A newly activated
  // side-by-side binary is manual and therefore repoints the task once.
  if (!IS_SCHEDULED || UPDATED_FROM) {
    try { setupTask(); } catch (e) { log(`Task setup warning: ${e.message}`); }
  }

  const cfg = loadConfig();
  if (!cfg || !cfg.name) {
    log('Invalid config — delete config and rerun setup');
    console.error('Config is invalid. Delete the config file and run setup again.');
    await waitForEnter();
    process.exit(1);
    return;
  }

  // An update is only reported after the new binary has started, repaired the
  // scheduled task, loaded the existing config, and can communicate with GAS.
  if (UPDATED_FROM && UPDATED_FROM !== VERSION) {
    const confirmed = await sendPing(
      cfg.name,
      'UPDATED',
      `Confirmed restart from ${UPDATED_FROM} to ${VERSION}`,
      { version: VERSION, lastUpdateCheck: new Date().toISOString() }
    );
    if (confirmed.ok) log(`Update confirmed by server: ${UPDATED_FROM} -> ${VERSION}`);
    else log(`Update confirmation queued: ${UPDATED_FROM} -> ${VERSION}`);
  }

  // Check for updates once on startup
  const isUpdating = await checkForUpdates(cfg.name);
  if (isUpdating) return; // side-by-side updater starts the verified new binary

  // Enter persistent service loop
  await serviceLoop(cfg);
}

// -------------------- GLOBAL ERROR HANDLERS --------------------
// Best-effort ping before crash so the admin dashboard sees the failure.
function handleFatalError(type, err) {
  const msg = err && err.message ? err.message : String(err);
  log(`${type}: ${msg}`);
  appendEvent({ kind: type.toLowerCase(), error: msg });
  // Attempt a best-effort ping; don't await — we're crashing regardless.
  const cfg = (() => { try { return loadConfig(); } catch { return null; } })();
  if (cfg && cfg.name) {
    sendPing(cfg.name, 'FAILURE', `${ERR.UNKNOWN_ERROR}: ${type}: ${msg}`).catch(() => {});
  }
  setTimeout(() => process.exit(1), 3000);
}

if (require.main === module) {
  process.on('unhandledRejection', (reason) => handleFatalError('UNHANDLED_REJECTION', reason));
  process.on('uncaughtException',  (err)    => handleFatalError('UNCAUGHT_EXCEPTION', err));
  main().catch(() => process.exit(1));
} else {
  module.exports = {
    compareVersions,
    isoWeekKey,
    uploadPeriodKey,
    isUploadDue,
    zonedDateParts,
    releaseBinaryName,
    manifestPlatformKeys,
  };
}
