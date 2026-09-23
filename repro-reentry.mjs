// re-entry 竞态复现：模拟 cordis 并发加载时 cosmokit 的 ESM link 与 CJS require 时序交错
// 放在 user-management 目录以解析 @deepseek-ai/*
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

// 让 cosmokit 的 ESM 加载（import，async link）与 CJS require 在同 tick 交错
const tasks = [
  import('@deepseek-ai/cosmokit').then(m => ({ tag: 'import', vm: typeof m.valueMap, keys: Object.keys(m).length })),
  Promise.resolve().then(() => {
    const c = require('@deepseek-ai/cosmokit');
    return { tag: 'require', vm: typeof c.valueMap, keys: Object.keys(c).length };
  }),
  // 也并发 require schemastery（它会内部 require cosmokit）
  Promise.resolve().then(() => {
    const Schema = require('@deepseek-ai/schemastery');
    return { tag: 'schemastery', schema: typeof Schema };
  }),
];
const r = await Promise.allSettled(tasks);
const out = r.map(x => x.status === 'fulfilled' ? JSON.stringify(x.value) : 'REJ:' + (x.reason?.message || '').slice(0, 120));
console.log(out.join(' || '));
