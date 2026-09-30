/* VOLITYX Pro secure server  (Node 18+, no npm install needed)
 *
 * SETUP
 *  1. node server.js hash "your-long-password"     -> prints a hash line
 *  2. create a file named .env next to this file:
 *       APP_PASSWORD_HASH=<the hash line>
 *       PORT=8080
 *       # optional, for real-time NSE prices + real orders (Zerodha Kite Connect):
 *       KITE_API_KEY=xxxx
 *       KITE_ACCESS_TOKEN=xxxx        (Kite tokens expire daily; refresh each morning)
 *       TRADING_ENABLED=0             (keep 0 until you have tested with tiny size)
 *       MAX_ORDER_VALUE=50000  MAX_QTY=500  MAX_ORDERS_PER_DAY=6
 *       COOKIE_SECURE=1               (set when served over HTTPS)
 *       TRUST_PROXY=1                 (set only behind your own reverse proxy, e.g. Caddy/nginx)
 *       HOST=127.0.0.1                (keep; let the proxy face the internet)
 *  3. node server.js    then open http://127.0.0.1:8080
 *
 * All settings and keys live here on the server. The browser cannot change them.
 */
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

// ---------- config (.env, never sent to the browser) ----------
try {
  for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch (e) {}
const E = process.env;
const CFG = {
  port: +E.PORT || 8080, host: E.HOST || '127.0.0.1',
  hash: E.APP_PASSWORD_HASH || '', secure: E.COOKIE_SECURE === '1',
  kiteKey: E.KITE_API_KEY || '', kiteTok: E.KITE_ACCESS_TOKEN || '',
  trading: E.TRADING_ENABLED === '1',
  maxValue: +E.MAX_ORDER_VALUE || 50000, maxQty: +E.MAX_QTY || 500, maxDay: +E.MAX_ORDERS_PER_DAY || 6,
};
const LOG = path.join(__dirname, 'audit.log');
const audit = (ev, o) => { try { fs.appendFileSync(LOG, JSON.stringify({ t: new Date().toISOString(), ev, ...o }) + '\n'); } catch (e) {} };

// ---------- password hashing ----------
if (process.argv[2] === 'hash') {
  const pw = process.argv[3]; if (!pw || pw.length < 10) { console.log('Use a password of 10+ characters:  node server.js hash "your password"'); process.exit(1); }
  const salt = crypto.randomBytes(16).toString('hex');
  console.log('APP_PASSWORD_HASH=' + salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex')); process.exit(0);
}
const checkPw = pw => {
  const [salt, h] = CFG.hash.split(':'); if (!salt || !h) return false;
  const a = crypto.scryptSync(String(pw).slice(0, 200), salt, 64), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---------- pages + CSP (inline script/style allowed only by exact hash) ----------
const sha = s => "'sha256-" + crypto.createHash('sha256').update(s).digest('base64') + "'";
const INDEX = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const hashes = re => [...INDEX.matchAll(re)].map(m => sha(m[1])).join(' ');
const CSP = "default-src 'none'; script-src " + hashes(/<script>([\s\S]*?)<\/script>/g) +
  "; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; " +
  "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
const LOGIN_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const LOGIN = err => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>VOLITYX login</title>
<style>body{font:15px system-ui;background:#0b0f1a;color:#e8ecf5;display:grid;place-content:center;min-height:100vh;margin:0}form{display:grid;gap:12px;width:280px}
input,button{padding:12px;border-radius:10px;border:1px solid #2a3350;background:#141b2e;color:inherit;font:inherit}button{background:#2b59ff;border:0;font-weight:700;cursor:pointer}p{color:#ff6b6b;margin:0}</style>
<form method=post action=/login><b>VOLITYX Pro</b><input type=password name=pw placeholder=Password autocomplete=current-password autofocus required>${err ? '<p>' + err + '</p>' : ''}<button>Sign in</button></form>`;
const SEC = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()', 'Cache-Control': 'no-store',
  ...(CFG.secure ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};

// ---------- sessions, login throttling ----------
const sessions = new Map(), fails = new Map(), TTL = 8 * 3600e3;
const cookie = (req, n) => ((req.headers.cookie || '').match(new RegExp('(?:^|; )' + n + '=([a-f0-9]{64})')) || [])[1];
const session = req => { const s = sessions.get(cookie(req, 'vx')); if (!s || s.exp < Date.now()) return null; return s; };
const ip = req => (E.TRUST_PROXY === '1' && String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()) || req.socket.remoteAddress || '';
const send = (res, code, body, type = 'application/json', extra = {}) => { res.writeHead(code, { ...SEC, 'Content-Type': type + '; charset=utf-8', ...extra }); res.end(body); };
const json = (res, code, o) => send(res, code, JSON.stringify(o));
const readBody = (req, max = 4096) => new Promise((ok, no) => { let b = ''; req.on('data', c => { b += c; if (b.length > max) { no(new Error('big')); req.destroy(); } }); req.on('end', () => ok(b)); req.on('error', no); });
const sameOrigin = req => { const sf = req.headers['sec-fetch-site']; if (sf) return sf === 'same-origin' || sf === 'none'; const o = req.headers.origin; return !o || (() => { try { return new URL(o).host === req.headers.host; } catch (e) { return false; } })(); };

// ---------- symbols ----------
const STOCKS = 'RELIANCE TCS INFY HDFCBANK ICICIBANK SBIN AXISBANK TATAMOTORS MARUTI M&M TATASTEEL HINDALCO JSWSTEEL ADANIENT ADANIPORTS LT SUNPHARMA CIPLA ITC BHARTIARTL ZOMATO PAYTM IRFC YESBANK ONGC BEL'.split(' ');
// app symbol -> Yahoo symbol. Edit here if an exchange symbol changes (e.g. renames/demergers).
const YMAP = { ZOMATO: 'ETERNAL.NS', 'EUR/USD': 'EURUSD=X', 'GBP/USD': 'GBPUSD=X', 'USD/JPY': 'JPY=X', 'USD/INR': 'INR=X', 'AUD/USD': 'AUDUSD=X', 'USD/CAD': 'CAD=X',
  'XAU/USD (Gold)': 'GC=F', 'XAG/USD (Silver)': 'SI=F', 'WTI Crude': 'CL=F', 'Natural Gas': 'NG=F', 'BTC/USD': 'BTC-USD', 'ETH/USD': 'ETH-USD', 'SOL/USD': 'SOL-USD', 'XRP/USD': 'XRP-USD', 'BNB/USD': 'BNB-USD', 'DOGE/USD': 'DOGE-USD' };
const KMAP = { ZOMATO: 'ETERNAL' };
const ALL = STOCKS.concat(Object.keys(YMAP).filter(k => k !== 'ZOMATO'));
const ysym = s => YMAP[s] || s + '.NS';
const UA = { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36' };
const num = v => (typeof v === 'number' && isFinite(v) ? v : undefined);
const raw = o => (o && typeof o === 'object' ? o.raw : o);

// ---------- market data: Yahoo (all markets) + optional Kite (real-time NSE prices) ----------
const cache = { feed: { t: 0, d: {} }, kite: { t: 0, d: {} } };
async function yahooOne(sym) {
  const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + encodeURIComponent(ysym(sym)) + '?interval=5m&range=1d', { headers: UA, signal: AbortSignal.timeout(8000) });
  const c = (await r.json()).chart.result[0], q = c.indicators.quote[0], m = c.meta;
  let pv = 0, v = 0; const vols = [];
  (c.timestamp || []).forEach((_, i) => { if (q.close[i] == null) return; const tp = (q.high[i] + q.low[i] + q.close[i]) / 3, vo = q.volume[i] || 0; pv += tp * vo; v += vo; vols.push(vo); });
  const avg = vols.length ? vols.reduce((a, b) => a + b, 0) / vols.length : 0, rec = vols.slice(-6), ra = rec.length ? rec.reduce((a, b) => a + b, 0) / rec.length : 0;
  const o = q.open.find(x => x != null);
  return { price: num(m.regularMarketPrice), high: num(m.regularMarketDayHigh), low: num(m.regularMarketDayLow), prev: num(m.chartPreviousClose), open: num(o), vwap: v ? pv / v : undefined, rv: avg ? Math.min(6, ra / avg) : undefined };
}
async function feed() {
  if (Date.now() - cache.feed.t > 20000) {
    cache.feed.t = Date.now(); const out = {}, q = ALL.slice();
    await Promise.all(Array.from({ length: 6 }, async () => { for (let s; (s = q.shift());) { try { out[s] = await yahooOne(s); } catch (e) { } } }));
    if (Object.keys(out).length) cache.feed.d = out;
  }
  const d = JSON.parse(JSON.stringify(cache.feed.d));
  if (CFG.kiteKey && CFG.kiteTok) {
    if (Date.now() - cache.kite.t > 4000) {
      cache.kite.t = Date.now();
      try {
        const qs = STOCKS.map(s => 'i=' + encodeURIComponent('NSE:' + (KMAP[s] || s))).join('&');
        const r = await fetch('https://api.kite.trade/quote?' + qs, { headers: { 'X-Kite-Version': '3', Authorization: 'token ' + CFG.kiteKey + ':' + CFG.kiteTok }, signal: AbortSignal.timeout(6000) });
        const j = await r.json(); if (j.status === 'success') cache.kite.d = j.data;
      } catch (e) { }
    }
    for (const s of STOCKS) { const k = cache.kite.d['NSE:' + (KMAP[s] || s)]; if (!k) continue; d[s] = d[s] || {};
      Object.assign(d[s], { price: num(k.last_price), high: num(k.ohlc && k.ohlc.high), low: num(k.ohlc && k.ohlc.low), open: num(k.ohlc && k.ohlc.open), prev: num(k.ohlc && k.ohlc.close), vwap: num(k.average_price) || d[s].vwap }); }
  }
  return d;
}

// ---------- fundamentals (Yahoo quoteSummary with crumb) ----------
let crumb = { c: '', ck: '', t: 0 };
async function getCrumb() {
  if (crumb.c && Date.now() - crumb.t < 3600e3) return crumb;
  const r1 = await fetch('https://fc.yahoo.com', { headers: UA, redirect: 'manual' });
  const ck = (r1.headers.getSetCookie ? r1.headers.getSetCookie() : []).map(x => x.split(';')[0]).join('; ');
  const r2 = await fetch('https://query1.finance.yahoo.com/v1/test/getcrumb', { headers: { ...UA, Cookie: ck } });
  const c = await r2.text(); if (!c || c.length > 40) throw new Error('crumb'); crumb = { c, ck, t: Date.now() }; return crumb;
}
const cg = (a, b, n) => (a > 0 && b > 0 && n > 0 ? (Math.pow(b / a, 1 / n) - 1) * 100 : undefined);
const pc = v => (num(v) === undefined ? undefined : v * 100);
async function fund(sym) {
  const ys = ysym(sym), { c, ck } = await getCrumb(), H = { ...UA, Cookie: ck };
  const mods = 'price,summaryDetail,defaultKeyStatistics,financialData,incomeStatementHistory,assetProfile';
  const [a, b] = await Promise.all([
    fetch(`https://query1.finance.yahoo.com/v10/finance/quoteSummary/${encodeURIComponent(ys)}?modules=${mods}&crumb=${encodeURIComponent(c)}`, { headers: H, signal: AbortSignal.timeout(10000) }).then(r => r.json()),
    fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ys)}?interval=1wk&range=5y`, { headers: H, signal: AbortSignal.timeout(10000) }).then(r => r.json()),
  ]);
  const R = a.quoteSummary.result[0], P = R.price || {}, S = R.summaryDetail || {}, K = R.defaultKeyStatistics || {}, F = R.financialData || {}, I = ((R.incomeStatementHistory || {}).incomeStatementHistory || []).slice().reverse();
  const px = raw(P.regularMarketPrice), cl = ((b.chart.result[0].indicators.quote[0].close) || []).filter(x => x != null);
  const n = cl.length, ma = cl.length >= 40 ? cl.slice(-40).reduce((x, y) => x + y, 0) / 40 : undefined;
  let pk = 0, dd = 0; for (const x of cl) { pk = Math.max(pk, x); dd = Math.min(dd, x / pk - 1); }
  const rev = I.map(i => raw(i.totalRevenue)).filter(x => x > 0), ni = I.map(i => raw(i.netIncome)).filter(x => x > 0);
  const de = raw(F.debtToEquity), debt = raw(F.totalDebt), cash = raw(F.totalCash), ebitda = raw(F.ebitda);
  return {
    sym, name: P.longName || P.shortName || sym, sector: (R.assetProfile || {}).sector || '', price: px,
    pe: raw(S.trailingPE), fpe: raw(S.forwardPE), pb: raw(K.priceToBook), peg: raw(K.pegRatio), evebitda: raw(K.enterpriseToEbitda),
    eps: raw(K.trailingEps), shares: raw(K.sharesOutstanding), mcap: raw(S.marketCap),
    roe: pc(raw(F.returnOnEquity)), roa: pc(raw(F.returnOnAssets)), opm: pc(raw(F.operatingMargins)), npm: pc(raw(F.profitMargins)),
    de: num(de) === undefined ? undefined : de / 100, cr: raw(F.currentRatio),
    revg: pc(raw(F.revenueGrowth)), eg: pc(raw(F.earningsGrowth)),
    revcagr: rev.length > 1 ? cg(rev[0], rev[rev.length - 1], rev.length - 1) : undefined, nicagr: ni.length > 1 ? cg(ni[0], ni[ni.length - 1], ni.length - 1) : undefined,
    fcf: raw(F.freeCashflow), ocf: raw(F.operatingCashflow), netinc: raw(K.netIncomeToCommon), netdebtebitda: ebitda > 0 && num(debt) !== undefined ? (debt - (cash || 0)) / ebitda : undefined,
    divy: pc(raw(S.dividendYield)) ?? pc(raw(S.trailingAnnualDividendYield)), payout: pc(raw(S.payoutRatio)), beta: raw(K.beta) ?? raw(S.beta),
    insider: pc(raw(K.heldPercentInsiders)), inst: pc(raw(K.heldPercentInstitutions)),
    ma200: ma, hi52: raw(S.fiftyTwoWeekHigh), lo52: raw(S.fiftyTwoWeekLow),
    mom12: n > 52 ? (cl[n - 1] / cl[n - 53] - 1) * 100 : undefined, cagr5: n > 100 ? cg(cl[0], cl[n - 1], (n - 1) / 52) : undefined, maxdd: dd * 100,
  };
}

// ---------- guarded orders ----------
let day = { d: '', n: 0 };
async function order(o, feedNow) {
  if (!CFG.trading) throw new Error('Live trading is disabled on the server (TRADING_ENABLED=0). Use paper trading.');
  if (!CFG.kiteKey || !CFG.kiteTok) throw new Error('Broker keys are not configured on the server.');
  const sym = String(o.sym), side = o.side === 'Short' ? 'SELL' : o.side === 'Long' ? 'BUY' : '';
  if (!STOCKS.includes(sym)) throw new Error('Only NSE stocks on the allow-list can be traded.');
  if (!side) throw new Error('Bad side.');
  const q = Math.floor(+o.qty), ent = +o.entry, st = +o.stop;
  if (!(q > 0 && q <= CFG.maxQty)) throw new Error('Quantity must be 1 to ' + CFG.maxQty + '.');
  if (!(ent > 0 && st > 0)) throw new Error('Bad prices.');
  if (q * ent > CFG.maxValue) throw new Error('Order value exceeds the server limit of Rs ' + CFG.maxValue + '.');
  if (side === 'BUY' ? st >= ent : st <= ent) throw new Error('Stop is on the wrong side of entry.');
  const last = feedNow[sym] && feedNow[sym].price; if (last && Math.abs(ent / last - 1) > 0.02) throw new Error('Entry is more than 2% away from the current price.');
  const today = new Date().toISOString().slice(0, 10); if (day.d !== today) day = { d: today, n: 0 };
  if (day.n >= CFG.maxDay) throw new Error('Daily order limit reached.'); day.n++;
  const tick = x => (Math.round(x / 0.05) * 0.05).toFixed(2), H = { 'X-Kite-Version': '3', Authorization: 'token ' + CFG.kiteKey + ':' + CFG.kiteTok, 'Content-Type': 'application/x-www-form-urlencoded' };
  const post = p => fetch('https://api.kite.trade/orders/regular', { method: 'POST', headers: H, body: new URLSearchParams(p), signal: AbortSignal.timeout(8000) }).then(r => r.json());
  const base = { tradingsymbol: KMAP[sym] || sym, exchange: 'NSE', quantity: String(q), product: 'MIS', validity: 'DAY' };
  const e = await post({ ...base, transaction_type: side, order_type: 'LIMIT', price: tick(ent) });
  audit('entry', { sym, side, q, ent, res: e.status, id: e.data && e.data.order_id, msg: e.message });
  if (e.status !== 'success') throw new Error('Broker rejected entry: ' + (e.message || 'unknown'));
  const s = await post({ ...base, transaction_type: side === 'BUY' ? 'SELL' : 'BUY', order_type: 'SL-M', trigger_price: tick(st) });
  audit('stop', { sym, res: s.status, id: s.data && s.data.order_id, msg: s.message });
  return { entry: e.data.order_id, stop: s.status === 'success' ? s.data.order_id : null, warning: s.status === 'success' ? '' : 'STOP ORDER FAILED. Place a stop manually now.' };
}

// ---------- router ----------
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x'), p = u.pathname, s = session(req);
    if (p === '/healthz') return json(res, 200, { ok: true });
    if (p === '/login' && req.method === 'POST') {
      const f = fails.get(ip(req)) || { n: 0, t: 0 };
      if (f.n >= 5 && Date.now() - f.t < 900e3) return send(res, 429, LOGIN('Too many attempts. Try again in 15 minutes.'), 'text/html', { 'Content-Security-Policy': LOGIN_CSP });
      if (!sameOrigin(req)) return send(res, 403, 'Forbidden', 'text/plain');
      const pw = new URLSearchParams(await readBody(req)).get('pw') || '';
      if (CFG.hash && checkPw(pw)) {
        fails.delete(ip(req)); const id = crypto.randomBytes(32).toString('hex'); sessions.set(id, { exp: Date.now() + TTL, csrf: crypto.randomBytes(24).toString('hex') });
        audit('login', { ip: ip(req) });
        return send(res, 303, '', 'text/plain', { Location: '/', 'Set-Cookie': `vx=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL / 1000}${CFG.secure ? '; Secure' : ''}` });
      }
      fails.set(ip(req), { n: f.n + 1, t: Date.now() }); audit('login_fail', { ip: ip(req) });
      return send(res, 401, LOGIN('Wrong password.'), 'text/html', { 'Content-Security-Policy': LOGIN_CSP });
    }
    if (p === '/login') return send(res, 200, LOGIN(''), 'text/html', { 'Content-Security-Policy': LOGIN_CSP });
    if (p === '/logout' && req.method === 'POST') { sessions.delete(cookie(req, 'vx')); return send(res, 303, '', 'text/plain', { Location: '/login', 'Set-Cookie': 'vx=; Max-Age=0; Path=/; HttpOnly' }); }
    if (!s) return p.startsWith('/api/') ? json(res, 401, { error: 'auth' }) : send(res, 303, '', 'text/plain', { Location: '/login' });
    if (p === '/' || p === '/index.html') return send(res, 200, INDEX, 'text/html', { 'Content-Security-Policy': CSP });
    if (p === '/api/config') return json(res, 200, { csrf: s.csrf, trading: CFG.trading && !!CFG.kiteTok, maxValue: CFG.maxValue, realtime: !!CFG.kiteTok });
    if (p === '/api/feed') return json(res, 200, await feed());
    if (p === '/api/fund') { const sym = (u.searchParams.get('sym') || '').toUpperCase(); if (!/^[A-Z0-9&\-]{1,20}$/.test(sym)) return json(res, 400, { error: 'bad symbol' }); return json(res, 200, await fund(sym)); }
    if (p === '/api/order' && req.method === 'POST') {
      if (!sameOrigin(req) || req.headers['x-csrf'] !== s.csrf) return json(res, 403, { error: 'CSRF check failed' });
      try { return json(res, 200, await order(JSON.parse(await readBody(req)), cache.feed.d)); } catch (e) { audit('order_blocked', { msg: e.message }); return json(res, 400, { error: e.message }); }
    }
    return send(res, 404, 'Not found', 'text/plain');
  } catch (e) { return json(res, 500, { error: 'Server error' }); }
}).listen(CFG.port, CFG.host, () => {
  console.log(`VOLITYX running at http://${CFG.host}:${CFG.port}  | trading ${CFG.trading ? 'ENABLED' : 'disabled'} | realtime ${CFG.kiteTok ? 'Kite' : 'Yahoo (delayed)'}`);
  if (!CFG.hash) console.log('WARNING: no APP_PASSWORD_HASH set. Nobody can log in until you create one (see top of this file).');
  if (CFG.host !== '127.0.0.1') console.log('WARNING: exposed beyond localhost. Put it behind HTTPS (Caddy/nginx) and set COOKIE_SECURE=1.');
});
