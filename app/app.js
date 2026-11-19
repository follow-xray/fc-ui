'use strict';
const el = id => document.getElementById(id);
const form = el('create');
let token = sessionStorage.getItem('fc-ui-token') || '';
let templates = {};
function message(text) { el('notice').textContent = text; }
function lock() {
  token = ''; sessionStorage.removeItem('fc-ui-token');
  el('workspace').hidden = el('logout').hidden = true; el('login').hidden = false;
  el('replace-pem').reset(); el('replace-pem').hidden=true;
  el('nodes').replaceChildren(); el('cert-list').replaceChildren(); invalidateCert(); form.reset(); el('token').value = '';
}
async function api(op, data = {}) {
  const r = await fetch('/api', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({op,data}) });
  const value = await r.json();
  if (!r.ok) { if (r.status === 401) lock(); throw Error(value.error || '请求失败'); }
  return value.result;
}
let lookup = 0, checkedDomain = '', discovered = [];
const certDomain = () => (form.elements.sni.value.trim() || form.elements.host.value.trim()).toLowerCase();
function invalidateCert() {
  lookup++; checkedDomain = ''; discovered = [];
  el('cert-options').hidden = true; el('cert-status').textContent = '';
  el('dns-token').value = ''; el('pem-key').value = '';
}
function certFields() {
  const choice = el('cert-choice').value, method = el('challenge').value;
  el('cert-path').hidden = choice !== 'path';
  el('cert-pem').hidden = choice !== 'pem';
  el('cert-acme').hidden = choice !== 'acme';
  el('webroot-row').hidden = method !== 'webroot';
  el('dns-fields').hidden = method !== 'dns';
  el('account-row').hidden = Boolean(el('dns-zone').value.trim());
}
async function findCert() {
  const request = ++lookup, domain = certDomain();
  if (!templates[el('template').value]?.needsCert || !domain) return false;
  checkedDomain = ''; el('cert-options').hidden = true;
  el('cert-status').textContent = '正在查找证书…';
  try {
    const matches = await api('certFind', {domain});
    const usable = matches.filter(m => !m.problem);
    const sources = usable.length ? [] : await api('certCandidates', {domain});
    if (request !== lookup) return false;
    discovered = sources;
    const choices = usable.map(m => new Option('复用 '+m.names.join(', ')+' · '+m.expires, m.id));
    if (!choices.length) {
      sources.forEach((m,i) => choices.push(new Option('导入 '+m.chainPath, 'found-'+i)));
      choices.push(new Option('ACME 签发', 'acme'),new Option('输入服务器文件路径','path'),new Option('粘贴 PEM','pem'));
    }
    el('cert-choice').replaceChildren(...choices);
    el('cert-status').textContent = usable.length ? '已选中匹配证书，创建时直接复用。' :
      [...matches.map(m => m.problem), '请选择证书来源。'].join(' ');
    checkedDomain = domain; el('identifier').value = domain; el('cert-options').hidden = false; certFields();
    return true;
  } catch(e) { if (request === lookup) el('cert-status').textContent = e.message; return false; }
}
async function selectedCert() {
  const domain = certDomain();
  if (!checkedDomain || domain !== checkedDomain) {
    if (!await findCert()) throw Error('请填写证书对应的域名并查找证书');
    if (!/^[a-f0-9]{32}$/.test(el('cert-choice').value)) throw Error('请填写证书来源后再创建');
  }
  const choice = el('cert-choice').value;
  if (/^[a-f0-9]{32}$/.test(choice)) return choice;
  const data = {domain, source:choice};
  if (choice.startsWith('found-')) Object.assign(data, discovered[Number(choice.slice(6))], {source:'path'});
  if (choice === 'path') Object.assign(data, {chainPath:el('chain-path').value, keyPath:el('key-path').value});
  if (choice === 'pem') Object.assign(data,{certificate:el('pem-chain').value,key:el('pem-key').value});
  if (choice === 'acme') {
    data.email = el('acme-email').value; data.method = el('challenge').value;
    if (data.method === 'webroot') data.webroot = el('webroot').value;
    if (data.method === 'dns') Object.assign(data,{provider:el('dns-provider').value,identifier:el('identifier').value,
      token:el('dns-token').value,zone:el('dns-zone').value, account:el('dns-zone').value ? '' : el('dns-account').value});
  }
  message('正在验证并部署证书，请稍候…');
  const item = await api('certRegister', data);
  el('dns-token').value = el('pem-key').value = '';
  if (certDomain() !== domain) throw Error('域名已更改，请重新选择证书');
  await findCert(); return item.id;
}
el('cert-choice').onchange = el('challenge').onchange = certFields;
el('find-cert').onclick = findCert;
el('dns-zone').oninput = certFields;
for (const input of [form.elements.host, form.elements.sni]) {
  input.addEventListener('input', invalidateCert);
  input.addEventListener('change', findCert);
}
function templateChanged() {
  invalidateCert();
  const t = templates[el('template').value];
  form.elements.port.value = t.port;
  el('vless').hidden = !t.needsCert && t.security !== 'reality' && t.protocol !== 'vless';
  el('uuid-row').hidden = t.protocol !== 'vless';
  form.elements.sni.closest('label').hidden = !t.needsCert && t.security !== 'reality';
  el('cert').hidden = !t.needsCert;
  el('short').hidden = t.security !== 'reality';
  el('ss').hidden = !['shadowsocks','trojan'].includes(t.protocol) && t.network !== 'hysteria';
  el('path-row').hidden = !['ws','xhttp','httpupgrade'].includes(t.network);
  el('grpc-row').hidden = t.network !== 'grpc';
  el('mode-row').hidden = t.network !== 'xhttp';
  el('drive-row').hidden = t.network !== 'xdrive';
  if(t.private_only) form.elements.host.placeholder='内网 IPv4 或 ULA IPv6';
  else form.elements.host.placeholder='公网 IP 或域名';
  form.elements.sni.value = t.security === 'reality' ? 'www.cloudflare.com' : '';
  const hints = [];
  if(t.private_only) hints.push('仅绑定所填的本机内网或回环 IP，请确认客户端可达。');
  if(t.needsEncryption) hints.push('将自动生成一对 VLESS Encryption 密钥。');
  if(t.security==='reality') hints.push('REALITY 目标使用 SNI 的 443 端口。');
  if(t.needsCert) { hints.push('使用证书覆盖的域名作为 SNI。'); findCert(); }
  if(t.key_bytes) hints.push('自定义密码须为 '+t.key_bytes+' 字节密钥的 Base64 编码。');
  if(t.network==='xdrive') hints.push('配置 local、google-drive、s3 或 template，客户端也必须可访问该存储。链接包含存储凭据。');
  if(t.ports.length) hints.push('放行代理端口 '+t.ports.join('/').toUpperCase()+'。');
  el('hint').textContent=hints.join(' ');

}
async function refresh() {
  const nodes = await api('list'), list = el('nodes'); list.replaceChildren();
  const certs = await api('certList');
  const rows = certs.map(c => {
    const p = document.createElement('p');
    const source = {acme:'ACME 自动续期', path:'同步服务器证书', pem:'手动更新'}[c.source];
    p.textContent = [c.names.join(', '), source, c.expires, c.problem || c.renewalStatus,
      c.nodes.length ? '引用：'+c.nodes.join('、') : '尚无节点引用'].filter(Boolean).join(' · ');
    if (c.source === 'pem') {
      const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = '更新 PEM';
      edit.onclick = () => {
        const f = el('replace-pem'); f.dataset.id = c.id; f.hidden = false;
        el('replace-domain').textContent = c.names.join(', '); f.scrollIntoView();
      };
      p.append(' ', edit);
    }
    return p;
  });
  el('cert-list').replaceChildren(...(rows.length ? rows : ['暂无证书']));
  if (!nodes.length) list.textContent = '暂无节点';
  for (const node of nodes) {
    const card = document.createElement('article'); card.className = 'node';
    const title = document.createElement('strong'); title.textContent = node.name + ' · ' + (node.running?'运行中':node.enabled?'等待重试':'已停止');
    const address = document.createElement('p'); address.textContent = node.host+' · '+node.port;
    const link = document.createElement('textarea'); link.readOnly = true; link.value=node.link; link.setAttribute('aria-label','fcxray 节点链接');
    const copy = document.createElement('button'); copy.textContent = '复制链接'; copy.onclick=async()=>{
      try {await navigator.clipboard.writeText(node.link);message('已复制，可在 fcxray 的“我的节点 → 导入节点”中粘贴。');}
      catch {link.focus();link.select();message('链接已选中，请手动复制。');}
    };
    const change = document.createElement('button'); change.className='secondary';change.textContent=node.enabled?'停止':'启动';
    change.onclick=async()=>{change.disabled=true;try{await api(node.enabled?'stop':'start',{id:node.id});await refresh();}catch(e){message(e.message);}finally{change.disabled=false;}};
    card.append(title,address,link,copy,change);
    if (templates[node.template]?.needsCert && !node.certId) {
      const migrate = document.createElement('button'); migrate.textContent='登记旧证书（下次启动生效）';
      migrate.onclick=async()=>{try{await api('certMigrate',{id:node.id});await refresh();}catch(e){message(e.message);}};
      card.append(migrate);
    }
    list.append(card);
  }
}
async function unlock() {
  const info=await api('templates'); templates=info.templates;
  const groups = new Map();
  for (const [key, t] of Object.entries(templates)) {
    const label = t.protocol === 'vless' ? 'VLESS / ' + t.network.toUpperCase() : t.protocol.toUpperCase();
    if (!groups.has(label)) {
      const group = document.createElement('optgroup');
      group.label = label;
      groups.set(label, group);
    }
    groups.get(label).append(new Option(t.name, key));
  }
  el('template').replaceChildren(...groups.values());
  form.elements.host.value=info.host;templateChanged();await refresh();
  sessionStorage.setItem('fc-ui-token',token);el('token').value='';el('workspace').hidden=el('logout').hidden=false;el('login').hidden=true;message('');
}
el('template').onchange=templateChanged;
el('auth').onsubmit=async e=>{e.preventDefault();token=el('token').value.trim();try{await unlock();}catch(e){message(e.message);}};
el('logout').onclick=()=>{lock();message('面板已锁定');};
el('refresh').onclick=()=>refresh().catch(e=>message(e.message));
form.onsubmit=async e=>{
  e.preventDefault(); const button=el('submit-node');button.disabled=true;
  try{const data=Object.fromEntries(new FormData(form));if(templates[data.template].needsCert) data.certId=await selectedCert();
    const node=await api('create',data);
    for(const k of ['password','uuid','shortId','xdrive'])form.elements[k].value='';
    await refresh();message(node.name+' 已启动，可复制节点链接。');}
  catch(e){message(e.message);}finally{button.disabled=false;}
};
if(token)unlock().catch(e=>message(e.message));

el('replace-pem').onsubmit = async event => {
  event.preventDefault();
  const f = event.target, button = f.querySelector('button');
  button.disabled = true;
  try {
    await api('certReplace', {id:f.dataset.id, certificate:f.elements.chain.value, key:f.elements.secret.value});
    f.reset(); f.hidden = true; await refresh(); message('证书已更新');
  } catch(e) { message(e.message); } finally { button.disabled = false; }
};
