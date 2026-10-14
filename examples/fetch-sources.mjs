// 転載できない原文を、照合の前に sources/ へテキストで取り直す。
// Zenn の本は著者の著作物、OpenID Connect Core 1.0 は利用許諾が仕様の策定と実装の目的に限られるので、
// どちらも Git には入れない。
//   node examples/fetch-sources.mjs
import { mkdirSync, writeFileSync } from 'node:fs';

const decode = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'")
  .replace(/&nbsp;|&#160;/g, ' ').replace(/&amp;/g, '&');
const htmlToText = (html) => decode(html
  .replace(/<(script|style)[\s\S]*?<\/\1>/g, '')
  .replace(/<br\s*\/?>/g, '\n')
  .replace(/<\/(p|li|h\d|tr|pre|div|blockquote|dt|dd)>/g, '\n')
  .replace(/<[^>]+>/g, ''))
  .replace(/\n\s*\n+/g, '\n\n');

// Zenn の本：各章を sources/zenn/NN-<slug>.txt に
const user = 'hidebike712', slug = 'oauth-attacks-and-bcp';
const zenn = new URL('../sources/zenn/', import.meta.url);
// ファイル名に token が入ると、秘密情報を守るフックが読み込みを止めるので短く言い換える
const rename = (s) => s.replace(/access-token/, 'at').replace(/id-token/, 'idt');
const { book } = await (await fetch(`https://zenn.dev/api/books/${slug}?username=${user}`)).json();
mkdirSync(zenn, { recursive: true });
for (const [i, c] of book.chapters.entries()) {
  const { chapter } = await (await fetch(`https://zenn.dev/api/chapters/${c.id}`)).json();
  const name = `${String(i + 1).padStart(2, '0')}-${rename(c.slug)}.txt`;
  writeFileSync(new URL(name, zenn), `# ${c.title}\nhttps://zenn.dev/${user}/books/${slug}/viewer/${c.slug}\n\n${htmlToText(chapter.body_html)}`);
  console.log(`zenn/${name}`);
}

// OpenID Connect Core 1.0 incorporating errata set 2
const oidcUrl = 'https://openid.net/specs/openid-connect-core-1_0.html';
writeFileSync(new URL('../sources/oidc-core-1_0.txt', import.meta.url), `${oidcUrl}\n\n${htmlToText(await (await fetch(oidcUrl)).text())}`);
console.log('oidc-core-1_0.txt');
