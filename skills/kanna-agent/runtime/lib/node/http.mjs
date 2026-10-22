// Bagian HTTP bersama untuk server Node (setara lib/php/Http.php).

// KANNA_ALLOW_WEBVIEW=1: permite incrustar la pagina en webviews de VS Code/Antigravity (scheme vscode-webview:).
// Sin esto el iframe de la extension kanna-panel queda en blanco (X-Frame-Options DENY).
const WEBVIEW = process.env.KANNA_ALLOW_WEBVIEW === '1';

export const SECURITY_HEADERS = {
  'X-Robots-Tag': 'noindex, nofollow',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  ...(WEBVIEW ? {} : { 'X-Frame-Options': 'DENY' }),
  'Content-Security-Policy': `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors ${WEBVIEW ? 'vscode-webview:' : "'none'"}; base-uri 'none'; form-action 'none'`,
};

// Konfigurasi halaman (window.KANNA): hanya nama & judul — status diambil lewat /kerja/api/state.
export function pageConfig(cfg) {
  return { title: cfg.title, ketua: cfg.ketua, team: cfg.team, colors: cfg.colors, spare_desks: cfg.spare_desks };
}

// Perlindungan DNS rebinding: hanya host IP literal, localhost, *.trycloudflare.com (tunnel), atau KANNA_ALLOWED_HOSTS.
export function hostAllowed(hostHeader, extra) {
  if (typeof hostHeader !== 'string' || hostHeader === '') return true; // HTTP/1.0 tanpa Host
  const h = hostHeader.toLowerCase();
  const m = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{1,5})?$/.exec(h);
  if (!m) return false;
  const name = m[1];
  if (name.startsWith('[')) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return true;
  if (name === 'localhost' || name.endsWith('.localhost') || name.endsWith('.trycloudflare.com')) return true;
  for (const x of String(extra || '').toLowerCase().split(',')) {
    const e = x.trim();
    if (e !== '' && (name === e || (e.startsWith('.') && name.endsWith(e)))) return true;
  }
  return false;
}
