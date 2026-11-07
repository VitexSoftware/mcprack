// Shared by env-rows.js (admin server form / install wizard) and
// override-editor.js (per-user configuration). Separate file because both
// editors can appear in one page load and CSP's script-src 'self' rules out
// inline <script>, so this has to be a real file loaded before them.

// Mirrors mcprack/env_detection.py's SENSITIVE_NAME_HINTS so imported .env
// keys get the same secret/plain default guess as server-side detection.
var ENV_SENSITIVE_NAME_HINTS = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'CREDENTIAL', 'APIKEY'];

function looksSensitiveEnvName(name) {
  var upper = (name || '').toUpperCase();
  return ENV_SENSITIVE_NAME_HINTS.some(function (hint) { return upper.indexOf(hint) !== -1; });
}

// Parses the subset of dotenv syntax admins are likely to actually paste:
// blank lines, '#' comments, an optional leading 'export ', and single- or
// double-quoted values (with \n/\t/\\/\" unescaping inside double quotes,
// matching common dotenv-parser behavior). Not a full spec implementation —
// good enough for reviewing/editing afterward in the row editor.
function parseDotEnv(text) {
  var rows = [];
  (text || '').split(/\r\n|\r|\n/).forEach(function (line) {
    var trimmed = line.trim();
    if (!trimmed || trimmed.charAt(0) === '#') {
      return;
    }
    if (trimmed.indexOf('export ') === 0) {
      trimmed = trimmed.slice(7).trim();
    }
    var eq = trimmed.indexOf('=');
    if (eq === -1) {
      return;
    }
    var key = trimmed.slice(0, eq).trim();
    var value = trimmed.slice(eq + 1).trim();
    if (!key) {
      return;
    }
    if (value.length >= 2 && value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') {
      value = value.slice(1, -1)
        .replace(/\\n/g, '\n')
        .replace(/\\t/g, '\t')
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    } else if (value.length >= 2 && value.charAt(0) === "'" && value.charAt(value.length - 1) === "'") {
      value = value.slice(1, -1);
    }
    rows.push({ key: key, value: value });
  });
  return rows;
}
