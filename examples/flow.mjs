// 認可コードフローの再現スクリプト。認可サーバ（AS）とクライアントを関数で書き、
// 診断で送るリクエストを 1 つずつ投げて、脆弱な設定と正しい設定で結果を比べる。
//   node examples/flow.mjs
// HTTP は使わない。302 の Location は文字列で返し、ブラウザの役は呼び出し側が担う。
import { createHash, randomBytes } from 'node:crypto';

// 32 バイトで 43 文字。code_verifier は RFC 7636 §4.1 で 43〜128 文字
const rand = () => randomBytes(32).toString('base64url');
const s256 = (v) => createHash('sha256').update(v).digest('base64url');

function makeAS({ issuer = 'https://as.example', redirectMatch = 'exact', pkceDowngrade = false, requirePkce = false,
  registered = ['https://app.example/callback', 'https://app.example/callback2', 'http://127.0.0.1/cb'] } = {}) {
  const clients = { app: registered };
  const codes = new Map();
  const tokens = new Map();
  const matches = (uri, reg) => {
    if (redirectMatch === 'prefix') return uri.startsWith(reg);
    // 「*」を「/ も含む任意の文字列」として扱う、誤ったワイルドカード照合
    if (redirectMatch === 'wildcard') return new RegExp(`^${reg.split('*').map((s) => s.replace(/[.?+^$()[\]{}|\\/]/g, '\\$&')).join('.*')}$`).test(uri);
    if (uri === reg) return true;
    // RFC 8252 §7.3：ループバック IP の redirect URI だけ、ポートの違いを許す
    const a = new URL(uri), b = new URL(reg);
    return a.hostname === '127.0.0.1' && b.hostname === '127.0.0.1' && a.protocol === 'http:'
      && a.pathname === b.pathname && a.search === b.search;
  };
  return {
    issuer,
    authorize({ client_id, redirect_uri, state, code_challenge, code_challenge_method, user }) {
      if (!clients[client_id]?.some((r) => matches(redirect_uri, r))) return { error: 'invalid_request（redirect_uri 不一致）' };
      if (requirePkce && !code_challenge) return { error: 'invalid_request（code_challenge が無い）' };
      const code = rand();
      codes.set(code, { client_id, redirect_uri, user, code_challenge, code_challenge_method, used: false, issued: [] });
      const u = new URL(redirect_uri);
      Object.entries({ code, ...(state && { state }), iss: issuer }).forEach(([k, v]) => u.searchParams.set(k, v));
      return { location: u.href };
    },
    token({ client_id, code, redirect_uri, code_verifier }) {
      const c = codes.get(code);
      if (!c) return { error: 'invalid_grant（code 不明）' };
      if (c.used) {
        // RFC 6749 §4.1.2：再利用は拒否し、その code で発行したトークンも失効させる
        c.issued.forEach((t) => tokens.delete(t));
        return { error: 'invalid_grant（code 再利用。発行済みトークンを失効）' };
      }
      if (c.client_id !== client_id) return { error: 'invalid_grant（別の client_id）' };
      if (c.redirect_uri !== redirect_uri) return { error: 'invalid_grant（redirect_uri が認可リクエストと違う）' };
      if (c.code_challenge) {
        if (!code_verifier || s256(code_verifier) !== c.code_challenge) return { error: 'invalid_grant（code_verifier 不一致）' };
      } else if (code_verifier && !pkceDowngrade) {
        // RFC 9700 §4.8.2：code_challenge なしで発行した code を、code_verifier 付きで交換させない
        return { error: 'invalid_grant（PKCE ダウングレード）' };
      }
      c.used = true;
      const access_token = rand();
      tokens.set(access_token, c.user);
      c.issued.push(access_token);
      return { access_token };
    },
    introspect: (t) => (tokens.has(t) ? `有効（${tokens.get(t)}）` : '失効'),
  };
}

// クライアント（RP）。セッションごとに state と code_verifier を持ち、/callback で照合する
function makeClient(servers, { checkState = true, usePkce = true, checkIss = true } = {}) {
  // 複数の認可サーバを使うクライアントは、フローを始めた先を覚えておく
  servers = [servers].flat();
  const sessions = new Map();
  let tokenRequests = 0;
  return {
    get tokenRequests() { return tokenRequests; },
    start(sid, as = servers[0]) {
      const s = { as, state: rand(), verifier: rand(), redirect_uri: 'https://app.example/callback' };
      sessions.set(sid, s);
      return {
        client_id: 'app', redirect_uri: s.redirect_uri, state: s.state,
        ...(usePkce && { code_challenge: s256(s.verifier), code_challenge_method: 'S256' }),
      };
    },
    callback(sid, location) {
      const q = new URL(location).searchParams;
      const s = sessions.get(sid) ?? { as: servers[0] };
      if (checkState && (!q.get('state') || q.get('state') !== s.state)) return 'state 不一致で拒否';
      // RFC 9207 §2.4：トークンリクエストを送る前に iss を照合する
      if (checkIss && q.get('iss') !== s.as.issuer) return 'iss 不一致で拒否（code を送らない）';
      tokenRequests++;
      const r = s.as.token({
        client_id: 'app', code: q.get('code'), redirect_uri: s.redirect_uri ?? 'https://app.example/callback',
        ...(usePkce && s.verifier && { code_verifier: s.verifier }),
      });
      if (r.error) return `トークン取得に失敗：${r.error}`;
      return `ログイン成立：セッション ${sid} が ${s.as.introspect(r.access_token).replace(/^有効（(.*)）$/, '$1')} として扱われる`;
    },
  };
}

const show = (title, result) => console.log(`${title} → ${result}`);
const authz = (as, params) => { const r = as.authorize(params); return r.error ?? `受理 ${r.location.split('?')[0]}`; };

console.log('## 1. redirect_uri の照合（認可サーバ）');
for (const mode of ['prefix', 'exact']) {
  const as = makeAS({ redirectMatch: mode });
  const uri = 'https://app.example/callback/../logout?next=https://attacker.example';
  show(`[${mode}] ${uri}`, authz(as, { client_id: 'app', redirect_uri: uri, user: 'victim' }));
}
{
  const as = makeAS({ redirectMatch: 'wildcard', registered: ['https://*.app.example/callback'] });
  show('[wildcard https://*.app.example/callback] https://attacker.example/.app.example/callback',
    authz(as, { client_id: 'app', redirect_uri: 'https://attacker.example/.app.example/callback', user: 'victim' }));
}
show('[exact] http://127.0.0.1:51004/cb', authz(makeAS(), { client_id: 'app', redirect_uri: 'http://127.0.0.1:51004/cb', user: 'victim' }));

console.log('## 2. state：攻撃者の code を被害者のセッションに送る（CSRF）');
for (const opt of [{ checkState: false, usePkce: false }, { checkState: false, usePkce: true }, { checkState: true, usePkce: false }]) {
  const as = makeAS(); const app = makeClient(as, opt);
  app.start('victim-session'); // 被害者も自分のフローを始めている
  const attackerReq = app.start('attacker-session');
  const loc = as.authorize({ ...attackerReq, user: 'attacker' }).location; // 攻撃者は /callback を踏まずに止める
  show(`[state検証=${opt.checkState} PKCE=${opt.usePkce}]`, app.callback('victim-session', loc));
}

console.log('## 3. 認可コードの注入：漏れた被害者の code を攻撃者のセッションで使う');
for (const opt of [{ checkState: true, usePkce: false }, { checkState: true, usePkce: true }]) {
  const as = makeAS(); const app = makeClient(as, opt);
  const victimLoc = as.authorize({ ...app.start('victim-session'), user: 'victim' }).location; // Referer などで漏れた
  const attackerState = app.start('attacker-session').state; // 攻撃者は自分のセッションの state を持っている
  const injected = victimLoc.replace(/state=[^&]+/, `state=${attackerState}`);
  show(`[state検証=${opt.checkState} PKCE=${opt.usePkce}]`, app.callback('attacker-session', injected));
}
// パブリッククライアント（client 認証なし）の code なら、攻撃者は注入せずに /token を直接呼べる
for (const usePkce of [false, true]) {
  const as = makeAS(); const app = makeClient(as, { usePkce });
  const code = new URL(as.authorize({ ...app.start('victim-session'), user: 'victim' }).location).searchParams.get('code');
  const r = as.token({ client_id: 'app', code, redirect_uri: 'https://app.example/callback' });
  show(`[パブリッククライアント PKCE=${usePkce}] 攻撃者が /token を直接呼ぶ`, r.error ?? 'access_token 発行');
}

console.log('## 4. PKCE ダウングレード：code_challenge を外して得た code を被害者に踏ませる');
// クライアントは state を使わず、CSRF 対策を PKCE だけに頼っている（RFC 9700 §4.8 の前提）
for (const opt of [{ pkceDowngrade: true }, { pkceDowngrade: false }, { pkceDowngrade: true, requirePkce: true }]) {
  const as = makeAS(opt); const app = makeClient(as, { checkState: false, usePkce: true });
  app.start('victim-session'); // 被害者のセッションには code_verifier が残っている
  const { code_challenge, code_challenge_method, ...stripped } = app.start('attacker-session');
  const r = as.authorize({ ...stripped, user: 'attacker' });
  const label = opt.requirePkce ? '[PKCE 必須]' : `[ダウングレード対策=${!opt.pkceDowngrade}]`;
  show(label, r.error ? `認可リクエストで拒否：${r.error}` : app.callback('victim-session', r.location));
}

console.log('## 5. code の再利用とトークンリクエストの redirect_uri');
{
  const as = makeAS();
  const code = () => new URL(as.authorize({ client_id: 'app', redirect_uri: 'https://app.example/callback', user: 'victim' }).location).searchParams.get('code');
  const c1 = code();
  const first = as.token({ client_id: 'app', code: c1, redirect_uri: 'https://app.example/callback' });
  show('1 回目の交換', first.access_token ? 'access_token 発行' : first.error);
  show('同じ code で 2 回目', as.token({ client_id: 'app', code: c1, redirect_uri: 'https://app.example/callback' }).error);
  show('1 回目の access_token', as.introspect(first.access_token));
  show('redirect_uri を /callback2 に変えて交換', as.token({ client_id: 'app', code: code(), redirect_uri: 'https://app.example/callback2' }).error);
}

console.log('## 6. mix-up：別の認可サーバの応答として届いた code');
// 被害者は攻撃者の認可サーバを選んでログインを始め、攻撃者はその要求を正規の認可サーバへ転送する。
// 正規の認可サーバの code が、クライアントには「攻撃者の認可サーバの応答」として届く
for (const checkIss of [false, true]) {
  const honest = makeAS();
  const stolen = [];
  const evil = { issuer: 'https://attacker-as.example', token: ({ code }) => (stolen.push(code), { error: 'invalid_grant' }) };
  const app = makeClient([honest, evil], { checkIss });
  const req = app.start('victim-session', evil);
  const loc = honest.authorize({ ...req, user: 'victim' }).location;
  show(`[iss検証=${checkIss}]`, `${app.callback('victim-session', loc)}。攻撃者の認可サーバに届いた code ${stolen.length} 個`);
}
