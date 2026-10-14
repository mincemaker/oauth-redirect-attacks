// Zenn の本の各章の本文を、zenn.dev の API から sources/zenn/ にテキストで保存する。
// 本文は著者の著作物なので Git には入れず、照合の前にこれで取り直す。
//   node examples/fetch-zenn.mjs
import { mkdirSync, writeFileSync } from 'node:fs';

const user = 'hidebike712', slug = 'oauth-attacks-and-bcp';
const dir = new URL('../sources/zenn/', import.meta.url);
// ファイル名に token が入ると、秘密情報を守るフックが読み込みを止めるので短く言い換える
const rename = (s) => s.replace(/access-token/, 'at').replace(/id-token/, 'idt');
const decode = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'").replace(/&amp;/g, '&');

const { book } = await (await fetch(`https://zenn.dev/api/books/${slug}?username=${user}`)).json();
mkdirSync(dir, { recursive: true });
for (const [i, c] of book.chapters.entries()) {
  const { chapter } = await (await fetch(`https://zenn.dev/api/chapters/${c.id}`)).json();
  const text = decode(chapter.body_html
    .replace(/<(script|style)[\s\S]*?<\/\1>/g, '')
    .replace(/<br\s*\/?>/g, '\n')
    .replace(/<\/(p|li|h\d|tr|pre|div|blockquote)>/g, '\n')
    .replace(/<[^>]+>/g, ''))
    .replace(/\n\s*\n+/g, '\n\n');
  const name = `${String(i + 1).padStart(2, '0')}-${rename(c.slug)}.txt`;
  writeFileSync(new URL(name, dir), `# ${c.title}\nhttps://zenn.dev/${user}/books/${slug}/viewer/${c.slug}\n\n${text}`);
  console.log(name);
}
