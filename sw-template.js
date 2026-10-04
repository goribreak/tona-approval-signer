'use strict';
const RELEASE_ID='__TONA_RELEASE_ID__';
const CACHE='tona-approval-'+RELEASE_ID;
const ASSETS=['index.html','app.mjs','styles.css','policy.mjs','crypto.mjs','session.mjs','release-check.mjs','sw-template.js','release.mjs','sw.js'];
const CORE=ASSETS.filter(name=>!['release.mjs','sw.js'].includes(name));
const sha=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('');
async function releaseDigest(files) {
  const core=Object.fromEntries(CORE.map(name=>[name,files[name]]));
  return sha(new TextEncoder().encode(JSON.stringify(core)));
}
async function verifyRelease(manifest,readFile,expected) {
  const refuse=()=>{throw Error('固定版の内容が一致しません。鍵を使用せず準備をやり直してください。');};
  if(!manifest || Object.keys(manifest).sort().join(' ')!=='files release schema_version'
    || manifest.schema_version!==1 || typeof expected!=='string' || !/^[0-9a-f]{64}$/.test(expected)
    || manifest.release!==expected || !manifest.files || Array.isArray(manifest.files)
    || Object.keys(manifest.files).sort().join(' ')!==[...ASSETS].sort().join(' ')
    || Object.values(manifest.files).some(hash=>typeof hash!=='string' || !/^[0-9a-f]{64}$/.test(hash))) refuse();
  if(await releaseDigest(manifest.files)!==expected) refuse();
  const loaded=new Map();
  for(const name of ASSETS) {
    const bytes=await readFile(name);
    if(!(bytes instanceof Uint8Array) || bytes.byteLength>1000000 || await sha(bytes)!==manifest.files[name]) refuse();
    loaded.set(name,bytes);
  }
  const decoder=new TextDecoder('utf-8',{fatal:true});
  const template=decoder.decode(loaded.get('sw-template.js'));
  const marker=['__TONA','_RELEASE_ID__'].join('');
  if(!template.includes(marker)
    || decoder.decode(loaded.get('sw.js'))!==template.replaceAll(marker,expected)
    || decoder.decode(loaded.get('release.mjs'))!==`export const RELEASE_ID='${expected}';\n`) refuse();
  return expected;
}


self.addEventListener('install',event=>event.waitUntil((async()=>{
  const response=await fetch('release-manifest.json',{cache:'no-store',credentials:'omit'});
  if(!response.ok)throw Error('manifest');const manifest=await response.json(),loaded=new Map();
  await verifyRelease(manifest,async name=>{const r=await fetch(name,{cache:'no-store',credentials:'omit'});if(!r.ok)throw Error('asset');const bytes=new Uint8Array(await r.arrayBuffer());loaded.set(name,bytes);return bytes;},RELEASE_ID);
  const cache=await caches.open(CACHE);
  for(const [name,bytes] of loaded)await cache.put(new URL(name,self.registration.scope),new Response(bytes,{headers:{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.css')?'text/css':name.endsWith('.mjs')?'text/javascript':'text/javascript'}}));
  await cache.put(new URL('release-manifest.json',self.registration.scope),new Response(JSON.stringify(manifest),{headers:{'Content-Type':'application/json'}}));
})()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url),base=new URL(self.registration.scope);
  if(event.request.method!=='GET' || url.origin!==base.origin || url.search || !url.pathname.startsWith(base.pathname)){event.respondWith(Promise.resolve(new Response('Unavailable',{status:503})));return;}
  event.respondWith((async()=>{const cache=await caches.open(CACHE);const key=url.pathname===base.pathname?new URL('index.html',base).href:event.request;return await cache.match(key) || new Response('Unavailable',{status:503});})());
});
self.addEventListener('message',event=>{if(event.data?.type==='release')event.ports[0]?.postMessage({release:RELEASE_ID});});
