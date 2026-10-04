export const ASSETS=['index.html','app.mjs','styles.css','policy.mjs','crypto.mjs','session.mjs','release-check.mjs','sw-template.js','release.mjs','sw.js'];
const CORE=ASSETS.filter(name=>!['release.mjs','sw.js'].includes(name));
const sha=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('');
export async function releaseDigest(files) {
  const core=Object.fromEntries(CORE.map(name=>[name,files[name]]));
  return sha(new TextEncoder().encode(JSON.stringify(core)));
}
export async function verifyRelease(manifest,readFile,expected) {
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
