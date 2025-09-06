// === Utility functions ===
const suspiciousTLDs = [
  'zip','review','country','kim','cricket','science','work','party',
  'gq','cf','ml','ga','tk','xyz','top','loan','wang','mom','date',
  'men','click'
];
const shorteners = [
  'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','buff.ly',
  'ow.ly','bit.do','cutt.ly','rebrand.ly','shorte.st'
];
const brandWords = [
  'login','verify','secure','update','reset','account','wallet',
  'gift','promo','free','prize','support','invoice','signin',
  'mfa','2fa','banking','paypal','apple','google','microsoft'
];

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let H = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

function isIPAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+$/i.test(host);
}

// === Feature extraction ===
function extractFeatures(raw) {
  let u;
  try { u = new URL(raw.trim()); } catch (e) { return { error: 'Invalid URL' }; }

  const host = u.hostname;
  const hostNoWWW = host.replace(/^www\./i, '');
  const path = (u.pathname || '') + (u.search || '');
  const tld = host.split('.').pop()?.toLowerCase() || '';

  return {
    url: u.href,
    scheme: u.protocol.replace(':', ''),
    usesHTTP: u.protocol === 'http:',
    length: u.href.length,
    hostnameLength: host.length,
    pathLength: path.length,
    numDots: (host.match(/\./g) || []).length,
    numHyphens: (host.match(/-/g) || []).length,
    hasAtSymbol: /@/.test(u.href),
    hasPort: u.port !== '',
    queryLength: (u.search || '').length,
    fragmentLength: (u.hash || '').length,
    entropyHost: Number(shannonEntropy(hostNoWWW).toFixed(2)),
    isIPAddress: isIPAddress(host),
    hasPunycode: /(^|\.)xn--/.test(host),
    suspiciousTLD: suspiciousTLDs.includes(tld),
    isShortener: shorteners.includes(hostNoWWW.toLowerCase()),
    brandWordInPath: brandWords.some(w => path.toLowerCase().includes(w)),
    numDigitsHost: (host.match(/\d/g) || []).length,
    numSubdomains: Math.max(0, host.split('.').length - 2),
  };
}

// === Scoring system ===
function score(f) {
  let s = 0, reasons = [];
  const add = (pts, why) => { s += pts; reasons.push({ pts, why }); };

  if (f.usesHTTP) add(15, 'Uses unsecured HTTP');
  if (f.isIPAddress) add(20, 'Hostname is an IP address');
  if (f.hasPunycode) add(15, 'Punycode hostname (xn--)');
  if (f.suspiciousTLD) add(15, `Suspicious TLD .${f.url.split('.').pop()?.split('/')[0]}`);
  if (f.isShortener) add(15, 'Known URL shortener');
  if (f.hasAtSymbol) add(12, 'Contains @ symbol');
  if (f.hasPort) add(10, 'Non-standard port in URL');
  if (f.brandWordInPath) add(15, 'Impersonation/credential bait keyword');

  if (f.length > 80) add(10, 'Very long URL');
  if (f.hostnameLength > 25) add(10, 'Long hostname');
  if (f.numDots >= 3) add(10, 'Many subdomains');
  if (f.numHyphens >= 2) add(8, 'Multiple hyphens');
  if (f.numDigitsHost >= 3) add(6, 'Many digits in hostname');
  if (f.entropyHost > 3.4) add(8, 'High hostname entropy');
  if (f.queryLength > 30) add(6, 'Long query string');

  s = Math.max(0, Math.min(100, Math.round(s)));

  let label = 'Low risk', badgeClass = 'bg-emerald-100 text-emerald-800';
  if (s >= 55) { label = 'HIGH risk'; badgeClass = 'bg-rose-100 text-rose-800'; }
  else if (s >= 30) { label = 'Medium risk'; badgeClass = 'bg-amber-100 text-amber-800'; }

  return { score: s, label, badgeClass, reasons };
}

// === Rendering results ===
function render(f, r) {
  const resEl = document.getElementById('result');
  const badge = document.getElementById('scoreBadge');
  const signals = document.getElementById('signals');
  const feat = document.getElementById('features');

  resEl.classList.remove('hidden');
  badge.className = `inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${r.badgeClass}`;
  badge.innerHTML = `<span>${r.label}</span><span class="mono">(${r.score}/100)</span>`;

  signals.innerHTML = '';
  if (r.reasons.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No strong phishing indicators detected.';
    signals.appendChild(li);
  } else {
    for (const x of r.reasons.sort((a, b) => b.pts - a.pts)) {
      const li = document.createElement('li');
      li.textContent = `${x.why} (+${x.pts})`;
      signals.appendChild(li);
    }
  }

  feat.innerHTML = '';
  for (const [k, v] of Object.entries(f).filter(([k]) => k !== 'url')) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="py-1 pr-4 text-slate-500">${k}</td><td class="py-1 mono">${String(v)}</td>`;
    feat.appendChild(tr);
  }
}

// === Event Listeners ===
document.getElementById('checkBtn').addEventListener('click', () => {
  const input = document.getElementById('url');
  const raw = input.value.trim();
  const errorMsg = document.getElementById('errorMsg');

  if (!raw) {
    errorMsg.classList.remove('hidden');
    return;
  }

  const f = extractFeatures(raw);
  if (f.error) {
    errorMsg.classList.remove('hidden');
    return;
  }

  errorMsg.classList.add('hidden');
  const r = score(f);
  render(f, r);
});

document.getElementById('url').addEventListener('input', () => {
  document.getElementById('errorMsg').classList.add('hidden');
});

document.getElementById('resetBtn').addEventListener('click', () => {
  document.getElementById('url').value = '';
  document.getElementById('result').classList.add('hidden');
  document.getElementById('errorMsg').classList.add('hidden');
});
