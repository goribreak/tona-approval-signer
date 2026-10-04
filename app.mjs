import {SignerSession} from './session.mjs';
import {verifyRelease} from './release-check.mjs';
import {parseStrictJSON} from './policy.mjs';
import {RELEASE_ID} from './release.mjs';
const $=id=>document.getElementById(id), session=new SignerSession({release:RELEASE_ID});
const urls=new Map();
let processing=false;
function message(text){$('status').textContent=text;}
function discard(id){for(const url of urls.get(id)??[])URL.revokeObjectURL(url);urls.delete(id);$(id).replaceChildren();}
function link(id,name,text){
  const url=URL.createObjectURL(new Blob([text],{type:'application/octet-stream'}));
  urls.set(id,[...(urls.get(id)??[]),url]);
  const a=document.createElement('a');a.href=url;a.download=name;a.className='download';a.textContent=name;$(id).append(a);
}
function controls(){
  for(const input of document.querySelectorAll('input'))input.disabled=processing || session.busy;
  $('clear').disabled=processing || session.busy;
  const ready=session.releaseVerified && navigator.onLine===false && /iPhone/.test(navigator.userAgent) && $('phone').checked;
  $('generate').disabled=processing || session.busy || !ready;
  $('sign').disabled=processing || session.busy || !ready || !session.policy || !session.encrypted || !$('saved').checked || !$('approved').checked;
}
function confirmations(){session.confirm({phone:$('phone').checked,keySaved:$('saved').checked,policy:$('approved').checked});}
function invalidate(){discard('downloads');session.output=null;controls();}
function display(policy){
  const panel=$('policy-summary');panel.replaceChildren();
  const details=document.createElement('p');details.textContent=`対象: ${policy.repository} / ${policy.core_branch}\nレビュー担当: ${policy.reviewer_logins.join(', ')}\n承認日時: ${policy.approved_at}`;panel.append(details);
  const list=document.createElement('ul');
  for(const task of policy.tasks){const item=document.createElement('li'),pre=document.createElement('pre');pre.textContent=`${task.title}\n${task.description}\nタスク: ${task.task_id}\nブランチ: ${task.target_branch}\n変更できるファイル:\n${task.allowed_paths.join('\n')}`;item.append(pre);list.append(item);}panel.append(list);
}
async function fileText(input,max){const file=input.files?.[0];if(!file || file.size>max)throw Error('ファイルの種類とサイズを確認してください。');return file.text();}
async function operation(action){
  if(processing || session.busy)return;
  processing=true;controls();
  try {confirmations();await action();}
  catch(error){message(error.message || '操作できませんでした。入力を確認してください。');}
  finally {$('password').value='';$('repeat').value='';processing=false;controls();}
}
for(const id of ['phone','saved','approved'])$(id).addEventListener('change',()=>{invalidate();confirmations();});
for(const id of ['password','repeat'])$(id).addEventListener('input',invalidate);
$('generate').addEventListener('click',()=>operation(async()=>{
  invalidate();discard('backup');$('saved').checked=false;
  session.encrypted=null;
  if($('password').value!==$('repeat').value)throw Error('2つのパスフレーズが一致しません。');
  const result=await session.generate($('password').value);
  link('backup','tona-encrypted-key.json',JSON.stringify(result.encrypted,null,2)+'\n');
  message('鍵を作りました。暗号化バックアップをこのiPhone内に保存してください。');
}));
$('key-file').addEventListener('change',()=>operation(async()=>{
  invalidate();discard('backup');$('saved').checked=false;
  session.encrypted=null;
  session.loadEncrypted(await fileText($('key-file'),16384));message('暗号化バックアップを読み込みました。保存先を確認してください。');
}));
$('policy-file').addEventListener('change',()=>operation(async()=>{
  invalidate();$('approved').checked=false;$('policy-summary').textContent='確認中…';
  session.policy=null;
  const policy=session.loadPolicy(await fileText($('policy-file'),1000000));display(policy);message('対象タスクと変更できる範囲を確認してください。');
}));
$('sign').addEventListener('click',()=>operation(async()=>{
  invalidate();const result=await session.sign($('password').value);
  link('downloads','policy.json',result.policyText);link('downloads','policy.sig',result.signatureHex+'\n');
  link('downloads','host.environment.json',JSON.stringify(result.pins,null,2)+'\n');
  message('署名しました。公開情報の3ファイルだけをPCへ渡してください。');
}));
$('clear').addEventListener('click',()=>{
  session.clear();discard('backup');discard('downloads');
  for(const input of document.querySelectorAll('input')){input.value='';input.checked=false;}
  $('policy-summary').textContent='ファイルを選ぶと、対象の機能と変更できる範囲を表示します。';message('この画面の入力と鍵を消しました。');controls();
});
window.addEventListener('beforeunload',()=>{for(const group of urls.values())for(const url of group)URL.revokeObjectURL(url);});
window.addEventListener('online',()=>{session.cancelPending();invalidate();message('通信が有効です。鍵を使う前に機内モードとWi-Fiオフを確認してください。');});
window.addEventListener('offline',()=>{controls();message(session.releaseVerified?'準備完了。通信オフで鍵を使えます。':'固定版の準備が未完了です。通信を戻して準備してください。');});
async function controllerRelease(controller){
  return new Promise((resolve,reject)=>{const channel=new MessageChannel();const timer=setTimeout(()=>{channel.port1.close();reject(Error('保存済み画面を確認できません。'));},5000);
    channel.port1.onmessage=event=>{clearTimeout(timer);channel.port1.close();resolve(event.data?.release);};controller.postMessage({type:'release'},[channel.port2]);});
}
async function prepare(){
  try{
    if(!isSecureContext || !navigator.serviceWorker || !crypto.subtle)throw Error('HTTPSと対応するSafariが必要です。');
    const read=async name=>{const response=await fetch(name,{cache:'no-store',credentials:'omit'});if(!response.ok)throw Error('固定版を読み込めません。');return new Uint8Array(await response.arrayBuffer());};
    const manifest=parseStrictJSON(new TextDecoder('utf-8',{fatal:true}).decode(await read('release-manifest.json')));
    await verifyRelease(manifest,read,RELEASE_ID);
    await navigator.serviceWorker.register('./sw.js',{scope:'./',updateViaCache:'none'});
    await navigator.serviceWorker.ready;
    if(!navigator.serviceWorker.controller)await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('保存済み画面を確認できません。再度開いてください。')),10000);navigator.serviceWorker.addEventListener('controllerchange',()=>{clearTimeout(timer);resolve();},{once:true});});
    session.verifyRelease(await controllerRelease(navigator.serviceWorker.controller));
    message(navigator.onLine?'準備完了。機内モードにしてWi-Fiも切ってください。':'準備完了。通信オフで鍵を使えます。');
  }catch{message('準備できません。通信がある状態で固定版を開き直してください。鍵は使用できません。');}
  controls();
}
controls();prepare();
