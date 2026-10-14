// RFC のテキスト版と、sources/zenn/ の章から、指定した書き出しで始まる 1 文を丸ごと出す（改行・改ページをまたいでよい）。
//   node examples/rfc-quote.mjs sources/rfc9700.txt "<書き出し>" ["<書き出し>" …]
import { readFileSync } from 'node:fs';

const [file, ...starts] = process.argv.slice(2);
const text = readFileSync(file, 'utf8')
  .replace(/\f/g, '')
  // 改ページのフッター（著者名 … [Page N]）とヘッダー（RFC NNNN … 年）を外す
  .replace(/^.*\[Page \d+\]\s*$/gm, '')
  .replace(/^RFC \d+ .*\d{4}\s*$/gm, '')
  // 行末のハイフンで分かれた語（attacker-\n controllable）をつなぐ
  .replace(/(\w-)\n[ \t]+(?=\w)/g, '$1')
  .replace(/\n\s*\n/g, '\0')
  .replace(/\s+/g, ' ')
  // 改ページで分かれた段落をつなぎ直す（小文字で始まる続きは同じ段落）
  .replace(/\0 ?(?=[a-z(])/g, ' ');
for (const s of starts) {
  const i = text.indexOf(s);
  if (i < 0) { console.log(`NOT FOUND: ${s}`); process.exitCode = 1; continue; }
  const end = /(?<!\b(?:e\.g|i\.e|cf|etc|Sec))\.(?= |\0|$)|。|\0/g;
  end.lastIndex = i;
  const m = end.exec(text);
  console.log(text.slice(i, m ? m.index + (m[0] === '\0' ? 0 : 1) : undefined).trim());
}
