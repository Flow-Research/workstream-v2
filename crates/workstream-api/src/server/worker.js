'use strict';
const el = id => document.getElementById(id);
const slot = 'worker-draft:v1:' + el('network').textContent;
const fields = ['account','task','nonce','action'];
const hexId = value => /^(0x)?[0-9a-f]{64}$/i.test(value);
let uploaded = false;
function save() {
  sessionStorage.setItem(slot, JSON.stringify({...Object.fromEntries(fields.map(k=>[k,el(k).value])), content:el('content').textContent, uploaded}));
}
function invalidate() { el('send').disabled=true; el('draft').value=''; el('digest').textContent=''; el('signed').value=''; }
function resetEvidence() {uploaded=false; el('file').value=''; el('content').textContent=''; el('uploadState').textContent='';}
try {
  const d=JSON.parse(sessionStorage.getItem(slot));
  if(d){for(const k of fields) el(k).value=d[k] || ''; if(hexId(d.content)){el('content').textContent=d.content; uploaded=d.uploaded===true; el('uploadState').textContent=uploaded?'Uploaded · restored acknowledgment':'Draft restored · reselect evidence to retry';}}
} catch { sessionStorage.removeItem(slot); }
for(const k of fields) el(k).oninput=()=>{invalidate(); if(k==='task'||k==='account')resetEvidence();save();};
document.addEventListener('workstream:submitted', event=>{
  if(hexId(event.detail))sessionStorage.setItem(slot+':receipt',event.detail);
});
const lastReceipt=sessionStorage.getItem(slot+':receipt');
if(lastReceipt && hexId(lastReceipt)){
  const link=document.createElement('a');link.href='/explorer?kind=receipt&key='+lastReceipt;
  link.textContent='Submitted · check verified receipt';el('result').replaceChildren(link);
}
el('forget').onclick=()=>{sessionStorage.removeItem(slot);sessionStorage.removeItem(slot+':receipt');location.reload();};
el('find').onclick=async()=>{
  const list=el('tasks');list.replaceChildren();
  try {if(!hexId(el('account').value))throw Error();const r=await fetch('/worker/tasks/'+el('account').value);if(!r.ok)throw Error();const data=await r.json();list.textContent=`Verified ${data.verified} / indexed ${data.indexed}. ${data.rows.length} matching task(s).`;
    for(const [task,state] of data.rows){const li=document.createElement('li'),b=document.createElement('button');b.textContent=state+' · '+task;b.onclick=()=>{el('task').value=task;el('task').oninput();};li.append(b);list.append(li);}
  }catch{list.textContent='Task list unavailable. Check account and projection.';}
};
async function digest(file){if(!file||file.size>256*1024)throw Error('Choose a file of at most 256 KiB');return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await file.arrayBuffer())),b=>b.toString(16).padStart(2,'0')).join('');}
el('file').onchange=async()=>{invalidate();uploaded=false;el('content').textContent='';el('uploadState').textContent='';save();const f=el('file').files[0];try{const h=await digest(f);if(el('file').files[0]===f){el('content').textContent=h;save();}}catch(e){el('uploadState').textContent=e.message;}};
el('upload').onclick=async()=>{
  const f=el('file').files[0], task=el('task').value, hash=el('content').textContent;
  if(!hexId(task)||!hexId(hash)||!f){el('uploadState').textContent='Select task and evidence first.';return;}
  try{const r=await fetch(`/v1/evidence/${task}/${hash}/upload`,{method:'POST',body:f,credentials:'omit',redirect:'error',headers:{Authorization:'Bearer '+el('token').value}});
    if(task!==el('task').value||f!==el('file').files[0])return;
    if(!r.ok){el('uploadState').textContent=r.status===410?'Upload lease expired · request renewal before retrying.':`Upload denied (${r.status}) · check grant and workspace login.`;return;}
    const ack=await r.json();if(ack.content_hash!==hash||ack.task!==task.replace(/^0x/,'').toLowerCase()||ack.status!=='Uploaded')throw Error();
    if(task!==el('task').value||f!==el('file').files[0])return;
    uploaded=true;el('uploadState').textContent='Uploaded · awaiting signed submission'+(ack.upload_lease_expires?' · upload lease ends '+new Date(1000*ack.upload_lease_expires).toISOString():'');save();
  }catch{el('uploadState').textContent='Upload interrupted or unconfirmed · retry the same file and digest.';}
};
el('preview').onclick=async()=>{
  invalidate();const values=Object.fromEntries(fields.map(k=>[k,el(k).value]));const content=el('content').textContent;
  if(['submit','bundle'].includes(values.action)&&!uploaded){el('result').textContent='Complete upload first.';return;}
  try{const r=await fetch('/worker/preview',{method:'POST',body:new URLSearchParams({...values,content})});if(!r.ok)throw Error();const p=await r.json();if(fields.some(k=>el(k).value!==values[k])||el('content').textContent!==content)return;
    el('draft').value=p.draft;el('digest').textContent=p.digest;el('send').disabled=false;el('result').textContent='Draft ready · review before signing';save();
  }catch{el('result').textContent='Cannot prepare action. Check account, task, digest and nonce.';}
};
