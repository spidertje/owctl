// Frontend regression: WiFi tab must show only WiFi-capable devices.
// Router with wifi_capable=false is HIDDEN; AP with wifi_capable=true is SHOWN;
// a never-checked AP (wifi_capable=null) is shown via role fallback.
const fs = require('fs'), vm = require('vm');
const app = fs.readFileSync('/opt/data/owctl/static/index.html', 'utf8')
            .match(/<script>([\s\S]*?)<\/script>/)[1];

const devices = [
  { id: 1, name: 'starlink-router', host: '192.168.55.1', role: 'router', access: 'ssh', status: 'online', wifi_capable: false },
  { id: 2, name: 'wifi-ap', host: '192.168.55.2', role: 'ap', access: 'ssh', status: 'online', wifi_capable: true },
  { id: 3, name: 'fresh-ap', host: '192.168.55.4', role: 'ap', access: 'ssh', status: 'unknown', wifi_capable: null },
  { id: 4, name: 'switch1', host: '192.168.55.3', role: 'switch', access: 'ssh', status: 'online', wifi_capable: false },
];
function route(url, opts) {
  const u = String(url).replace(/^\/api/, '');
  if (u === '/devices') return devices;
  if (u === '/vlans') return [];
  if (/^\/devices\/\d+\/wifi-config$/.test(u)) return { ssid: 'Guest', encryption: 'psk2', vlan_id: null, last_check: 'x' };
  return {};
}
const fetchMock = async (url, opts) => ({ ok: true, status: 200, json: async () => route(url, opts), text: async () => '{}' });
const els = {};
function makeEl(id) {
  return { id: id || '', _html: '', style: {}, dataset: {}, textContent: '',
    classList: { add(){}, remove(){}, toggle(){}, contains: () => false },
    set innerHTML(v){ this._html = String(v); }, get innerHTML(){ return this._html; },
    appendChild(c){ this._html += (c._html || ''); return c; },
    remove(){}, scrollIntoView(){}, addEventListener(){},
    querySelector(){ return makeEl('inner'); }, querySelectorAll(){ return []; } };
}
const document = { getElementById: id => els[id] || (els[id] = makeEl(id)),
  querySelector: s => makeEl('q_' + s), querySelectorAll: () => [],
  createElement: t => makeEl('el_' + t), body: makeEl('body'), addEventListener: () => {} };
const sandbox = { document, window: { location: { href: 'http://x/' }, addEventListener: () => {} },
  localStorage: { getItem: () => null, setItem(){} }, fetch: fetchMock,
  setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {}, console, JSON, Date, Math };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(app, sandbox, { filename: 'app.js' });

const fails = [];
const ok = (n, c) => { console.log((c ? 'PASS ' : 'FAIL ') + n); if (!c) fails.push(n); };
(async () => {
  await vm.runInContext('renderWifi()', sandbox);
  await new Promise(r => setTimeout(r, 300));
  const out = els['tab-wifi'] ? els['tab-wifi'].innerHTML : '';
  ok('wifi tab rendered', out.length > 100);
  ok('HIDES router with no radio (wifi_capable=false)', out.indexOf('starlink-router') === -1);
  ok('HIDES switch (wifi_capable=false)', out.indexOf('switch1') === -1);
  ok('SHOWS wifi-ap (wifi_capable=true)', out.indexOf('wifi-ap') >= 0);
  ok('SHOWS fresh-ap (never-checked, role ap fallback)', out.indexOf('fresh-ap') >= 0);
  ok('editWifi button for wifi-ap', out.indexOf('editWifi(2)') >= 0);
  ok('NO editWifi for hidden router', out.indexOf('editWifi(1)') === -1);
  ok('no empty-tab fallback', out.indexOf('No wireless-capable devices found') === -1);
  console.log('\n=== SUMMARY ===');
  console.log(fails.length ? 'FAILURES: ' + fails.join('; ') : 'WIFI CAPABILITY FILTER VERIFIED');
  process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR:', e && e.stack || e); process.exit(2); });
