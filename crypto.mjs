import {canonicalPolicy, validatePolicy, parseStrictJSON} from './policy.mjs';

const encoder=new TextEncoder();
const fail=()=>{throw new Error('鍵・パスフレーズ・署名内容を確認してください。');};
function subtle() {
  if(!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) fail();
  return globalThis.crypto.subtle;
}
const hex=bytes=>Array.from(new Uint8Array(bytes),n=>n.toString(16).padStart(2,'0')).join('');
function base64(bytes) {return btoa(String.fromCharCode(...new Uint8Array(bytes)));}
function decoded(value, min, max=min) {
  if(typeof value!=='string' || value.length>16384 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail();
  const bytes=Uint8Array.from(atob(value),ch=>ch.charCodeAt(0));
  if(bytes.length<min || bytes.length>max || base64(bytes)!==value) fail();
  return bytes;
}
function passwordBytes(password) {
  if(typeof password!=='string') fail();
  const bytes=encoder.encode(password);
  if(bytes.length<12 || bytes.length>1024) {bytes.fill(0);fail();}
  return bytes;
}
async function derive(password,salt) {
  const bytes=passwordBytes(password);
  try {
    const key=await subtle().importKey('raw',bytes,'PBKDF2',false,['deriveKey']);
    return await subtle().deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:600000},key,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  } finally {bytes.fill(0);}
}
function metadata(encrypted) {
  return encoder.encode(JSON.stringify({version:encrypted.version,kdf:encrypted.kdf,cipher:encrypted.cipher,
    iterations:encrypted.iterations,salt:encrypted.salt,iv:encrypted.iv,publicKey:encrypted.publicKey}));
}
function validateEncrypted(value) {
  if(!value || typeof value!=='object' || Array.isArray(value)
    || Object.keys(value).sort().join(' ')!=='cipher ciphertext iterations iv kdf publicKey salt version'
    || value.version!==1 || value.kdf!=='PBKDF2-SHA256' || value.cipher!=='AES-256-GCM'
    || value.iterations!==600000 || typeof value.publicKey!=='string' || !/^[0-9a-f]{64}$/.test(value.publicKey)
    || encoder.encode(JSON.stringify(value)).length>16384) fail();
  return {salt:decoded(value.salt,32),iv:decoded(value.iv,12),ciphertext:decoded(value.ciphertext,32,4096)};
}

export function parseEncryptedKey(text) {
  if(typeof text!=='string' || encoder.encode(text).length>16384) fail();
  const value=parseStrictJSON(text); validateEncrypted(value); return value;
}

export async function createEncryptedKey(password) {
  const bytes=passwordBytes(password); bytes.fill(0);
  let privateBytes;
  try {
    const pair=await subtle().generateKey({name:'Ed25519'},true,['sign','verify']);
    const publicKey=hex(await subtle().exportKey('raw',pair.publicKey));
    privateBytes=new Uint8Array(await subtle().exportKey('pkcs8',pair.privateKey));
    const salt=crypto.getRandomValues(new Uint8Array(32)), iv=crypto.getRandomValues(new Uint8Array(12));
    const encrypted={version:1,kdf:'PBKDF2-SHA256',cipher:'AES-256-GCM',iterations:600000,salt:base64(salt),iv:base64(iv),publicKey};
    const key=await derive(password,salt);
    encrypted.ciphertext=base64(await subtle().encrypt({name:'AES-GCM',iv,additionalData:metadata(encrypted)},key,privateBytes));
    return {encrypted,publicKey};
  } catch {fail();}
  finally {privateBytes?.fill(0);}
}

export async function signPolicy(policy,encrypted,password) {
  let privateBytes;
  try {
    validatePolicy(policy);
    const params=validateEncrypted(encrypted), key=await derive(password,params.salt);
    privateBytes=new Uint8Array(await subtle().decrypt({name:'AES-GCM',iv:params.iv,additionalData:metadata(encrypted)},key,params.ciphertext));
    const privateKey=await subtle().importKey('pkcs8',privateBytes,'Ed25519',false,['sign']);
    const hash=await subtle().digest('SHA-256',canonicalPolicy(policy));
    const signature=await subtle().sign('Ed25519',privateKey,hash);
    const publicKey=await subtle().importKey('raw',Uint8Array.from(encrypted.publicKey.match(/../g),x=>parseInt(x,16)),'Ed25519',false,['verify']);
    if(!await subtle().verify('Ed25519',publicKey,signature,hash)) fail();
    return {policyText:JSON.stringify(policy,null,2)+'\n',signatureHex:hex(signature),pins:{
      TONA_SUPERVISOR_APPROVAL_PUBLIC_KEY:encrypted.publicKey,TONA_SUPERVISOR_APPROVAL_POLICY_SHA256:hex(hash)}};
  } catch {fail();}
  finally {privateBytes?.fill(0);}
}
