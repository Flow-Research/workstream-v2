'use strict';
const el = id => document.getElementById(id);
const hash = s => /^[0-9a-f]{64}$/.test(s);
async function submissionId(task,digest){
  const prefix=new TextEncoder().encode('WS:v1:id:submission:');
  const message=new Uint8Array(prefix.length+64);message.set(prefix);
  message.set(Uint8Array.from((task+digest).match(/../g),pair=>parseInt(pair,16)),prefix.length);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',message)),b=>b.toString(16).padStart(2,'0')).join('');
}
let record, verified = false, generation = 0, objectUrl;
function invalidate(){generation++;el('send').disabled=true;el('signed').value='';el('draft').value='';el('digest').textContent='';}
function clearEvidence(){verified=false;el('evidence').textContent='';el('download').hidden=true;if(objectUrl)URL.revokeObjectURL(objectUrl);objectUrl=null;el('download').removeAttribute('href');}
function conflict(){const id=el('account').value.toLowerCase().replace(/^0x/,'');return !record?'Select a submission':id===record.author?'Conflict: submission author':id===record.sponsor?'Conflict: task sponsor':!hash(id)?'Enter reviewer account':'';}
function role(){el('role').textContent=conflict() || 'Independent of author and sponsor · chain verifies eligibility';}
el('account').oninput=()=>{invalidate();clearEvidence();role();};
el('action').oninput=el('nonce').oninput=invalidate;
async function openCase(){invalidate();clearEvidence();record=null;role();el('facts').replaceChildren();el('history').replaceChildren();const id=el('queue').value;if(!hash(id))return;
  try{const response=await fetch('/review/case/'+id);if(!response.ok)throw Error();const rows=await response.json();if(el('queue').value!==id)return;const data=Object.fromEntries(rows);
    if(![data.task,data.digest,data.author,data.sponsor,data.guide].every(hash)||data.submission!==id)throw Error();
    if(await submissionId(data.task,data.digest)!==id)throw Error();
    if(el('queue').value!==id)return;
    record=data;role();for(const [key,label] of [['author','Author'],['sponsor','Sponsor'],['task','Task'],['digest','Pinned evidence SHA-256'],['guide','Screening guide'],['version','Guide version']]){const term=document.createElement('dt'),value=document.createElement('dd');term.textContent=label;value.textContent=data[key];el('facts').append(term,value);}
    for(const [label,tx] of rows.filter(([k,v])=>k.includes(' · ')&&hash(v))){const li=document.createElement('li'),a=document.createElement('a');a.textContent=label;a.href='/explorer?kind=receipt&key='+tx;li.append(a);el('history').append(li);}
  }catch{el('role').textContent='Case unavailable. Refresh and retry.';}
}
el('queue').onchange=openCase;
(async()=>{try{const r=await fetch('/review/queue');if(!r.ok)throw Error();const q=await r.json();el('heights').textContent=`Verified ${q.verified} / Indexed ${q.indexed} · ${q.rows.length} unfinalized case(s)`;for(const [id,h] of q.rows)if(hash(id))el('queue').add(new Option(`Block ${h} · ${id}`,id));const id=new URLSearchParams(location.search).get('submission');if(hash(id)){if(!q.rows.some(([s])=>s===id))el('queue').add(new Option(id,id));el('queue').value=id;await openCase();}}catch{el('heights').textContent='Queue unavailable';}})();
el('verify').onclick=async()=>{invalidate();clearEvidence();const n=generation;if(conflict()){role();return;}try{const r=await fetch(`/v1/evidence/${record.task}/${record.digest}/link`,{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+el('token').value}});if(!r.ok)throw Error();const {url}=await r.json();if(!/^\/v1\/evidence\/download\/[0-9a-f]{64}$/.test(url))throw Error();const file=await fetch(url,{redirect:'error'});if(!file.ok)throw Error();const blob=await file.blob();const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer())),b=>b.toString(16).padStart(2,'0')).join('');if(generation!==n)return;if(digest!==record.digest)throw Error();verified=true;objectUrl=URL.createObjectURL(blob);el('download').href=objectUrl;el('download').hidden=false;el('evidence').textContent='Verified evidence digest';}catch{if(generation===n)el('evidence').textContent='Evidence unavailable or digest mismatch';}};
el('preview').onclick=async()=>{invalidate();const n=generation,why=conflict();if(why){el('result').textContent=why;return;}const action=el('action').value;if(action!=='lease'&&!verified){el('result').textContent='Verify evidence before deciding';return;}
  try{const r=await fetch('/review/preview',{method:'POST',body:new URLSearchParams({account:el('account').value,nonce:el('nonce').value,submission:record.submission,action})});if(!r.ok)throw Error();const d=await r.json();if(n!==generation)return;el('draft').value=d.draft;el('digest').textContent=d.digest;el('send').disabled=false;el('result').textContent='Unsigned · awaiting local signature';}catch{el('result').textContent='Review preview rejected';}};
