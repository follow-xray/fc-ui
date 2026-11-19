'use strict';
const el = id => document.getElementById(id);
const form = el('create');
let token = sessionStorage.getItem('fc-ui-token') || '';
let templates = {};
function message(text) { el('notice').textContent = text; }
function lock() {
  token = ''; sessionStorage.removeItem('fc-ui-token');
  el('workspace').hidden = el('logout').hidden = true; el('login').hidden = false;
  el('nodes').replaceChildren(); form.reset(); el('token').value = '';
}
async function api(op, data = {}) {
  const r = await fetch('/api', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({op,data}) });
  const value = await r.json();
  if (!r.ok) { if (r.status === 401) lock(); throw Error(value.error || '请求失败'); }
  return value.result;
}
function templateChanged() {
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
  if(t.needsCert) hints.push('请提供证书链、私钥和证书对应的 SNI。');
  if(t.key_bytes) hints.push('自定义密码须为 '+t.key_bytes+' 字节密钥的 Base64 编码。');
  if(t.network==='xdrive') hints.push('配置 local、google-drive、s3 或 template，客户端也必须可访问该存储。链接包含存储凭据。');
  if(t.ports.length) hints.push('放行代理端口 '+t.ports.join('/').toUpperCase()+'。');
  el('hint').textContent=hints.join(' ');

}
async function refresh() {
  const nodes = await api('list'), list = el('nodes'); list.replaceChildren();
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
    card.append(title,address,link,copy,change); list.append(card);
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
  e.preventDefault(); const button=form.querySelector('button');button.disabled=true;
  try{const data=Object.fromEntries(new FormData(form));const node=await api('create',data);
    for(const k of ['password','uuid','shortId','certificate','key','xdrive'])form.elements[k].value='';
    await refresh();message(node.name+' 已启动，可复制节点链接。');}
  catch(e){message(e.message);}finally{button.disabled=false;}
};
if(token)unlock().catch(e=>message(e.message));
