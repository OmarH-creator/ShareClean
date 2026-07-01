const samples = {
  apiLog: `2026-07-01 INFO  Loading /home/fakeuser/app/config.yml
2026-07-01 DEBUG DATABASE_URL=postgresql://app:fake-db-password@db.example.com/shareclean
2026-07-01 DEBUG api_key=fake-api-key-12345
2026-07-01 INFO  Contact user@example.com for support
2026-07-01 DEBUG Authorization: Bearer fake-bearer-token-xyz
2026-07-01 DEBUG session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.fakeSignatureValue123
2026-07-01 DEBUG service_ip=192.168.1.20`,
  stackTrace: `Traceback (most recent call last):
  File "C:\\Users\\Omar\\projects\\demo\\app.py", line 42, in connect
    client_secret=not-a-real-client-secret
RuntimeError: failed login for admin@example.com
debug token=fake-reset-token-884422
redis://cache:fake-redis-password@localhost:6379/0`,
  envSnippet: `APP_ENV=development
PASSWORD=fake-password-for-demo
REFRESH_TOKEN=fake-refresh-token-value
MYSQL_URL=mysql://root:fake-mysql-password@127.0.0.1:3306/app
CONTACT_EMAIL=security@example.dev
PRIVATE_HOST=10.0.4.8`,
};

const rules = [
  {
    id: "SC004",
    category: "connection_string",
    pattern: /\b((?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^:@/\s]*:)([^@\s]+)(@[^,\s]+)/gi,
    replacement: (_match, captures) => `${captures[0]}${genericLabel()}${captures[2]}`,
  },
  {
    id: "SC002",
    category: "token",
    pattern: /(authorization\s*:\s*bearer\s+)(\S+)/gi,
    replacement: (_match, captures) => `${captures[0]}${genericLabel()}`,
  },
  {
    id: "SC001",
    category: "credential",
    pattern: /\b(password|passwd|pwd|api[_-]?key|apikey|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)(\s*[:=]\s*)([^\s,;]+)/gim,
    replacement: (_match, captures) => `${captures[0]}${captures[1]}${genericLabel()}`,
  },
  {
    id: "SC003",
    category: "token",
    pattern: /\b(?:[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}\b/g,
    replacement: "[JWT REDACTED]",
  },
  {
    id: "SC005",
    category: "pii_email",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacement: "[EMAIL REDACTED]",
    optional: "email",
  },
  {
    id: "SC006",
    category: "pii_path",
    pattern: /([A-Za-z]:\\Users\\)([^\\\s]+)/gi,
    replacement: (_match, captures) => `${captures[0]}[USER]`,
  },
  {
    id: "SC006",
    category: "pii_path",
    pattern: /(\/(?:home|Users)\/)([^/\s]+)/g,
    replacement: (_match, captures) => `${captures[0]}[USER]`,
  },
  {
    id: "SC007",
    category: "internal_network",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    replacement: "[PRIVATE-IP]",
    optional: "privateIp",
  },
  {
    id: "SC008",
    category: "private_key",
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: "[PRIVATE-KEY REDACTED]",
  },
];

const inputText = document.querySelector("#inputText");
const outputText = document.querySelector("#outputText");
const replacementCount = document.querySelector("#replacementCount");
const replacementSummary = document.querySelector("#replacementSummary");
const lineCount = document.querySelector("#lineCount");
const riskLabel = document.querySelector("#riskLabel");
const scoreBar = document.querySelector("#scoreBar");
const findingsList = document.querySelector("#findingsList");
const safetyStatus = document.querySelector("#safetyStatus");
const emailToggle = document.querySelector("#emailToggle");
const privateIpToggle = document.querySelector("#privateIpToggle");
const redactionLabel = document.querySelector("#redactionLabel");
const scenarioSelect = document.querySelector("#scenarioSelect");
const sampleButton = document.querySelector("#sampleButton");
const copyButton = document.querySelector("#copyButton");
const copyStatus = document.querySelector("#copyStatus");

let latestCleanedText = "";

function genericLabel() {
  return redactionLabel.value || "[REDACTED]";
}

function lineNumberForOffset(text, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) {
    if (text[index] === "\n") {
      line += 1;
    }
  }
  return line;
}

function activeRules() {
  return rules.filter((rule) => {
    if (rule.optional === "email") {
      return emailToggle.checked;
    }
    if (rule.optional === "privateIp") {
      return privateIpToggle.checked;
    }
    return true;
  });
}

function replacementFor(rule, match, captures) {
  if (typeof rule.replacement === "function") {
    return rule.replacement(match, captures);
  }
  return rule.replacement;
}

function sanitize(text) {
  const findings = [];
  let cleaned = text;

  for (const rule of activeRules()) {
    cleaned = cleaned.replace(rule.pattern, (...args) => {
      const hasGroups = typeof args[args.length - 1] === "object";
      const offset = args[args.length - (hasGroups ? 3 : 2)];
      const originalText = args[args.length - (hasGroups ? 2 : 1)];
      const captures = args.slice(1, args.length - (hasGroups ? 3 : 2));
      const replacement = replacementFor(rule, args[0], captures);

      findings.push({
        ruleId: rule.id,
        category: rule.category,
        line: lineNumberForOffset(originalText, offset),
        replacement,
      });

      return replacement;
    });
  }

  return { cleaned, findings };
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function highlightedOutput(value) {
  let highlighted = escapeHtml(value);
  const labels = [
    genericLabel(),
    "[EMAIL REDACTED]",
    "[JWT REDACTED]",
    "[PRIVATE-KEY REDACTED]",
    "[USER]",
    "[PRIVATE-IP]",
  ].filter(Boolean);

  for (const label of labels.sort((a, b) => b.length - a.length)) {
    const escapedLabel = escapeHtml(label);
    const pattern = new RegExp(escapeRegExp(escapedLabel), "g");
    highlighted = highlighted.replace(pattern, '<span class="redaction">$&</span>');
  }

  return highlighted;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function renderFindings(findings) {
  findingsList.replaceChildren();

  if (findings.length === 0) {
    const empty = document.createElement("li");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    title.textContent = "No findings";
    detail.textContent = "Try a sample or paste fake log text.";
    empty.append(title, detail);
    findingsList.append(empty);
    safetyStatus.textContent = "No sensitive patterns found.";
    return;
  }

  safetyStatus.textContent = `${findings.length} finding(s), original values not stored.`;

  for (const finding of findings) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    title.textContent = finding.category;
    detail.textContent = `${finding.ruleId} on line ${finding.line}`;
    item.append(title, detail);
    findingsList.append(item);
  }
}

function riskText(count) {
  if (count === 0) {
    return "Clean";
  }
  if (count < 4) {
    return "Needs review";
  }
  return "High signal";
}

function updateStats(text, findings) {
  const count = findings.length;
  const lines = text.length === 0 ? 0 : text.split("\n").length;
  const score = Math.min(100, count * 18);

  replacementCount.textContent = String(count);
  replacementSummary.textContent = `${count} replacement(s)`;
  lineCount.textContent = String(lines);
  riskLabel.textContent = riskText(count);
  scoreBar.style.width = `${score}%`;
}

function update() {
  const { cleaned, findings } = sanitize(inputText.value);
  latestCleanedText = cleaned;
  outputText.innerHTML = highlightedOutput(cleaned);
  updateStats(inputText.value, findings);
  renderFindings(findings);
}

function loadSelectedSample() {
  inputText.value = samples[scenarioSelect.value];
  update();
  inputText.focus();
}

async function copyOutput() {
  try {
    await navigator.clipboard.writeText(latestCleanedText);
    copyStatus.textContent = "Copied sanitized output.";
  } catch (_error) {
    copyStatus.textContent = "Copy unavailable in this browser.";
  }
  window.setTimeout(() => {
    copyStatus.textContent = "";
  }, 2200);
}

inputText.value = samples.apiLog;
inputText.addEventListener("input", update);
emailToggle.addEventListener("change", update);
privateIpToggle.addEventListener("change", update);
redactionLabel.addEventListener("input", update);
scenarioSelect.addEventListener("change", loadSelectedSample);
sampleButton.addEventListener("click", loadSelectedSample);
copyButton.addEventListener("click", copyOutput);

update();
