import {parsePolicy} from './policy.mjs';
import {createEncryptedKey,signPolicy,parseEncryptedKey} from './crypto.mjs';

const fail=()=>{throw new Error('固定版・通信オフ・iPhone保存・承認内容を確認してください。');};
function frozen(value) {
  if(value && typeof value==='object') {Object.values(value).forEach(frozen);Object.freeze(value);}
  return value;
}

export class SignerSession {
  constructor({release,createKey=createEncryptedKey,sign=signPolicy,
    offline=()=>globalThis.navigator?.onLine===false,
    phone=()=>/iPhone/.test(globalThis.navigator?.userAgent??'')}={}) {
    this.release=release;this.createKey=createKey;this.signOperation=sign;this.offline=offline;this.phone=phone;
    this.releaseVerified=false;this.busy=false;this.policy=null;this.encrypted=null;this.output=null;this.operationGeneration=0;
    this.confirmations={phone:false,keySaved:false,policy:false};
  }
  available() {if(this.busy) fail();}
  verifyRelease(value) {
    this.available();this.releaseVerified=false;this.output=null;
    if(!/^[0-9a-f]{64}$/.test(this.release??'') || value!==this.release) fail();
    this.releaseVerified=true;
  }
  confirm({phone=false,keySaved=false,policy=false}={}) {
    this.available();this.confirmations={phone:phone===true,keySaved:keySaved===true,policy:policy===true};
  }
  loadPolicy(text) {
    this.available();this.output=null;this.policy=null;this.confirmations.policy=false;
    this.policy=frozen(parsePolicy(text));return this.policy;
  }
  loadEncrypted(text) {
    this.available();this.output=null;this.encrypted=null;this.confirmations.keySaved=false;
    this.encrypted=frozen(parseEncryptedKey(text));return this.encrypted.publicKey;
  }
  guard() {
    this.available();
    this.required();
  }
  required() {
    if(!this.releaseVerified || !this.offline() || !this.phone() || !this.confirmations.phone) fail();
  }
  cancelPending() {this.operationGeneration++;this.output=null;}
  completion(generation) {this.required();if(generation!==this.operationGeneration) fail();}
  async generate(password) {
    this.guard();this.busy=true;this.output=null;this.encrypted=null;this.confirmations.keySaved=false;
    const generation=this.operationGeneration;
    try {const result=await this.createKey(password);this.completion(generation);this.encrypted=frozen(result.encrypted);return result;}
    finally {this.busy=false;}
  }
  async sign(password) {
    this.guard();
    if(!this.policy || !this.encrypted || !this.confirmations.keySaved || !this.confirmations.policy) fail();
    this.output=null;this.busy=true;
    const generation=this.operationGeneration;
    try {const result=await this.signOperation(this.policy,this.encrypted,password);this.completion(generation);this.output=frozen(result);return this.output;}
    finally {this.busy=false;}
  }
  clear() {
    this.available();this.policy=null;this.encrypted=null;this.output=null;
    this.confirmations={phone:false,keySaved:false,policy:false};
  }
}
