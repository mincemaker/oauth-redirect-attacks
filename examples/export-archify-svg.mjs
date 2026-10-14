// archify の図（ページの CSS で色を付けた inline SVG）を、ライトテーマの計算済みスタイルを
// 属性に書き込んだ単体の SVG にする。archify には SVG を書き出すコマンドが無く、ページ内のボタンだけなので。
//   node examples/export-archify-svg.mjs <archify.html> <out.svg>
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

const [src, out] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ colorScheme: 'light' });
await page.goto(`file://${resolve(src)}`);
const svg = await page.evaluate(() => {
  const props = ['fill', 'fill-opacity', 'stroke', 'stroke-width', 'stroke-dasharray', 'stroke-opacity', 'stroke-linecap',
    'stroke-linejoin', 'opacity', 'font-family', 'font-size', 'font-weight', 'font-style', 'text-anchor', 'dominant-baseline',
    'letter-spacing', 'visibility', 'display'];
  const s = document.querySelector('svg[data-preset]');
  const clone = s.cloneNode(true);
  const from = [s, ...s.querySelectorAll('*')], to = [clone, ...clone.querySelectorAll('*')];
  from.forEach((el, i) => {
    const cs = getComputedStyle(el);
    to[i].setAttribute('style', props.map((k) => `${k}:${cs.getPropertyValue(k)}`).join(';'));
    to[i].removeAttribute('class');
  });
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  return clone.outerHTML;
});
writeFileSync(out, svg);
await browser.close();
console.log(`wrote ${out} (${svg.length} chars)`);
