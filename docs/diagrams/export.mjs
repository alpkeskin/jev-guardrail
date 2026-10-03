// Exports each diagram HTML to a 2x PNG of its <svg> (diagram-design PNG export).
// Usage: node docs/diagrams/export.mjs docs/diagrams/*.html   (requires playwright)
import { chromium } from 'playwright';
import path from 'node:path';

const browser = await chromium.launch();
for (const src of process.argv.slice(2)) {
  const page = await browser.newPage({ deviceScaleFactor: 2 });
  await page.goto('file://' + path.resolve(src));
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => document.fonts.ready);
  const out = src.replace(/\.html$/, '.png');
  await page.locator('svg').first().screenshot({ path: out });
  console.log('wrote', out);
  await page.close();
}
await browser.close();
