// Strict, bounded JSON and the existing continuous-low-risk-v1 policy schema.
const encoder = new TextEncoder();
const fail = () => { throw new Error('承認する内容の形式や範囲を確認してください。'); };
const fields = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const actual = Object.keys(value).sort();
  if (actual.join('\0') !== names.split(' ').sort().join('\0')) fail();
};
const unicode = value => {
  for (let i=0; i<value.length; i++) {
    const n=value.charCodeAt(i);
    if(n>=0xd800 && n<=0xdbff) {
      const next=value.charCodeAt(++i);
      if(!(next>=0xdc00 && next<=0xdfff)) fail();
    } else if(n>=0xdc00 && n<=0xdfff) fail();
  }
};

export function parseStrictJSON(text) {
  if(typeof text!=='string' || encoder.encode(text).length>1000000) fail();
  let pos=0;
  const whitespace=()=>{while(/[\t\r\n ]/.test(text[pos]??'!')) pos++;};
  const string=()=>{
    const start=pos++;
    while(pos<text.length) {
      const code=text.charCodeAt(pos);
      if(code<32) fail();
      if(text[pos]==='"') {
        pos++;
        const result=JSON.parse(text.slice(start,pos)); unicode(result); return result;
      }
      if(text[pos]==='\\') {
        pos++;
        if(text[pos]==='u') {
          if(!/^[0-9a-fA-F]{4}$/.test(text.slice(pos+1,pos+5))) fail();
          pos+=5; continue;
        }
        if(!'"\\/bfnrt'.includes(text[pos]??'!')) fail();
      }
      pos++;
    }
    fail();
  };
  const value=depth=>{
    if(depth>16) fail();
    whitespace();
    if(text[pos]==='"') return string();
    if(text[pos]==='{') {
      pos++; whitespace(); const result=Object.create(null);
      if(text[pos]==='}') {pos++;return result;}
      while(true) {
        if(text[pos]!=='"') fail();
        const key=string();
        if(Object.hasOwn(result,key)) fail();
        whitespace(); if(text[pos++]!==':') fail();
        result[key]=value(depth+1); whitespace();
        const next=text[pos++]; if(next==='}') return result;
        if(next!==',') fail(); whitespace();
      }
    }
    if(text[pos]==='[') {
      pos++; whitespace(); const result=[];
      if(text[pos]===']') {pos++;return result;}
      while(true) {
        result.push(value(depth+1)); whitespace();
        const next=text[pos++]; if(next===']') return result;
        if(next!==',') fail(); whitespace();
      }
    }
    for(const [literal,result] of [['true',true],['false',false],['null',null]]) {
      if(text.startsWith(literal,pos)) {pos+=literal.length;return result;}
    }
    const number=/^-?(?:0|[1-9][0-9]*)/.exec(text.slice(pos));
    if(!number) fail(); pos+=number[0].length;
    if(/[.eE0-9]/.test(text[pos]??'!')) fail();
    const result=Number(number[0]); if(!Number.isSafeInteger(result)) fail(); return result;
  };
  const result=value(0); whitespace(); if(pos!==text.length) fail(); return result;
}

function stamp(value) {
  if(typeof value!=='string') fail();
  const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if(!m) fail();
  const [year,month,day,hour,minute,second]=m.slice(1,7).map(Number);
  const leap=year%4===0 && (year%100!==0 || year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  if(year<1 || month<1 || month>12 || day<1 || day>days[month-1] || hour>23 || minute>59 || second>59) fail();
  if(m[7]!=='Z' && (Number(m[7].slice(1,3))>23 || Number(m[7].slice(4,6))>59)) fail();
}

const protectedPaths=['src/tona/maintenance/','tests/maintenance/','src/tona/trusted_execution/',
  'tests/trusted_execution/','src/tona/pc_control/','tests/pc_control/','src/tona/api_cost/',
  'tests/api_cost/','src/tona/browser_control/','tests/browser_control/'];
const sensitive=['secret','credential','token','password','permission','security','billing',
  'private','payment','auth','safety','database','schema','migration'];

function path(value) {
  if(typeof value!=='string' || !/^(?:src\/tona\/|tests\/).+\.py$/.test(value)
    || /[\\:]/.test(value) || value.split('/').some(part=>part==='' || part==='.' || part==='..')) fail();
  const normalized=value.normalize('NFKC').toLowerCase().replace(/ß/g,'ss').replace(/ſ/g,'s');
  if(protectedPaths.some(prefix=>normalized.startsWith(prefix)) || normalized==='src/tona/config.py'
    || sensitive.some(word=>normalized.includes(word))) fail();
}

export function validatePolicy(p) {
  fields(p,'schema_version policy_version enabled repository core_branch approved_by approved_at reviewer_logins tasks');
  if(p.schema_version!==1 || p.policy_version!=='continuous-low-risk-v1' || p.enabled!==true
    || p.repository!=='warenoid-lab/tona-ai' || p.core_branch!=='feat/core-v0.1' || p.approved_by!=='human') fail();
  stamp(p.approved_at);
  if(!Array.isArray(p.reviewer_logins) || p.reviewer_logins.length<1 || p.reviewer_logins.length>10
    || p.reviewer_logins.some(login=>typeof login!=='string'
      || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?$/.test(login)
      || login.toLowerCase()==='warenoid-lab' || login.toLowerCase().includes('replace'))) fail();
  if(!Array.isArray(p.tasks) || p.tasks.length<1 || p.tasks.length>100) fail();
  const ids=new Set(), branches=new Set();
  for(const task of p.tasks) {
    fields(task,'task_id target_branch title description allowed_paths risk_categories roadmap_index');
    for(const [name,limit] of [['task_id',96],['title',160],['description',4000]]) {
      const value=task[name];
      if(typeof value!=='string' || !value.trim() || [...value].length>limit) fail(); unicode(value);
    }
    if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/.test(task.task_id)) fail();
    const branch=task.target_branch;
    if(typeof branch!=='string' || branch.length>255 || !/^feature\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(branch) || branch.includes('..')) fail();
    if(ids.has(task.task_id) || branches.has(branch)) fail(); ids.add(task.task_id); branches.add(branch);
    if(!Array.isArray(task.allowed_paths) || task.allowed_paths.length<1 || task.allowed_paths.length>10
      || new Set(task.allowed_paths).size!==task.allowed_paths.length) fail();
    task.allowed_paths.forEach(path);
    if(!Array.isArray(task.risk_categories) || task.risk_categories.length!==1 || task.risk_categories[0]!=='normal_development'
      || !Number.isSafeInteger(task.roadmap_index) || task.roadmap_index<0) fail();
  }
  return p;
}

export function parsePolicy(text) {return validatePolicy(parseStrictJSON(text));}

const ascii=value=>JSON.stringify(value).replace(/[\u007f-\uffff]/g,ch=>'\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0'));
function canonical(value) {
  if(Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if(value && typeof value==='object') return '{'+Object.keys(value).sort().map(key=>ascii(key)+':'+canonical(value[key])).join(',')+'}';
  return ascii(value);
}
export function canonicalPolicy(policy) {return encoder.encode(canonical(validatePolicy(policy)));}
