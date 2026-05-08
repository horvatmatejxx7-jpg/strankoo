export const config = { matcher: '/(.*)', runtime: 'edge' };

// ── KNOWN ATTACK TOOLS & SCANNERS ─────────────────────────
const BLOCKED_UA = [
  'sqlmap', 'nikto', 'masscan', 'nmap', 'zgrab', 'w3af',
  'acunetix', 'nessus', 'openvas', 'dirbuster', 'gobuster',
  'wfuzz', 'hydra', 'medusa', 'metasploit', 'havij',
  'burpsuite', 'zap/', 'jorgee', 'slowloris', 'hulk',
  'python-requests/2.', 'go-http-client/1.', 'curl/7.', 'wget/',
  'libwww-perl', 'scrapy/', 'jakarta', 'java/', 'mechanize',
];

// ── PATH SCANNING ATTEMPTS ─────────────────────────────────
const BLOCKED_PATHS = [
  'wp-admin', 'wp-login', 'wp-config', '.env', 'phpinfo',
  '.git/', 'phpmyadmin', 'adminer', 'config.php', 'setup.php',
  'eval(', '.php', '.asp', '.aspx', '.jsp', 'shell.php',
  'c99', 'r57', 'backdoor', '/etc/passwd', '/etc/shadow',
  'base64_decode', 'system(', 'exec(', '../..', '..\\',
  '/proc/', '/sys/', 'xmlrpc', 'admin.php', 'login.php',
];

// ── IN-MEMORY RATE LIMIT STORE ─────────────────────────────
const store = new Map();
const LIMIT = 120;   // requests per window
const WINDOW = 60_000; // 1 minute in ms

export default function middleware(req) {
  const ua    = (req.headers.get('user-agent') || '').toLowerCase();
  const path  = new URL(req.url).pathname.toLowerCase();
  const ip    = (
    req.headers.get('cf-connecting-ip') ||
    req.headers.get('x-real-ip') ||
    req.headers.get('x-forwarded-for') || ''
  ).split(',')[0].trim();

  // 1. Block empty or suspiciously short user-agents
  if (ua.length < 8) {
    return forbidden();
  }

  // 2. Block known attack tools
  if (BLOCKED_UA.some(b => ua.includes(b))) {
    return forbidden();
  }

  // 3. Block path scanning
  if (BLOCKED_PATHS.some(p => path.includes(p))) {
    return new Response('404 Not Found', { status: 404 });
  }

  // 4. Block requests with suspiciously large query strings (SQLi probes)
  const qs = new URL(req.url).search;
  if (qs.length > 512) {
    return forbidden();
  }

  // 5. Rate limiting per IP
  if (ip) {
    const now = Date.now();
    let slot = store.get(ip);

    if (!slot || now > slot.r) {
      slot = { n: 0, r: now + WINDOW };
      store.set(ip, slot);
    }

    slot.n++;

    // Aggressive mode: if same IP hammers 5x the limit, ban for 10 min
    if (slot.n > LIMIT * 5) {
      slot.r = now + 600_000; // 10 min cooldown
      slot.n = 0;
      return tooMany(600);
    }

    if (slot.n > LIMIT) {
      return tooMany(60);
    }

    // Cleanup old entries to prevent memory leak
    if (store.size > 15000) {
      for (const [k, v] of store) {
        if (now > v.r) store.delete(k);
      }
    }
  }

  // All good — continue
}

function forbidden() {
  return new Response('403 Forbidden', { status: 403 });
}

function tooMany(retryAfter) {
  return new Response('429 Too Many Requests', {
    status: 429,
    headers: {
      'Retry-After': String(retryAfter),
      'X-RateLimit-Limit': String(LIMIT),
      'X-RateLimit-Remaining': '0',
    },
  });
}
