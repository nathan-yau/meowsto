/* Meowsto — pure logic (browser + node). Crypto envelope {v:1,salt,iv,iter,ct} AES-256-GCM, PBKDF2-SHA256 310000 */
(function(root){
var ITER=310000;
var AUTH_LABEL="shared/auth/v1|";
var LEGACY_LABELS=["restaurant-log/auth/v1|"];
var C=(typeof crypto!=="undefined"&&crypto.subtle)?crypto:require("crypto").webcrypto;
function uid(){return (typeof crypto!=="undefined"&&crypto.randomUUID)?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now().toString(36)}
function today(){var d=new Date();return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0")}
function defaults(){return {version:1,u:0,restaurants:[],visits:[],profile:"My food journal"}}
function b2a(u){u=new Uint8Array(u);if(typeof btoa==="undefined")return Buffer.from(u).toString("base64");var s="";for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)}
function a2b(s){if(typeof atob==="undefined")return new Uint8Array(Buffer.from(s,"base64"));var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
var KC={};
async function deriveKey(pass,saltB64,iter){if(typeof pass!=="string")return pass;var id=pass+"|"+saltB64+"|"+iter;if(KC[id])return KC[id];
 var base=await C.subtle.importKey("raw",new TextEncoder().encode(pass),"PBKDF2",false,["deriveKey","deriveBits"]);
 var k=await C.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:a2b(saltB64),iterations:iter},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);KC[id]=k;return k}
async function encrypt(obj,pass,saltB64){var salt=saltB64||b2a(C.getRandomValues(new Uint8Array(16))),iv=C.getRandomValues(new Uint8Array(12));
 var k=await deriveKey(pass,salt,ITER);var ct=await C.subtle.encrypt({name:"AES-GCM",iv:iv},k,new TextEncoder().encode(JSON.stringify(obj)));
 return {v:1,salt:salt,iv:b2a(iv),iter:ITER,ct:b2a(ct)}}
async function decrypt(env,pass){var k=await deriveKey(pass,env.salt,env.iter);var pt=await C.subtle.decrypt({name:"AES-GCM",iv:a2b(env.iv)},k,a2b(env.ct));return JSON.parse(new TextDecoder().decode(pt))}
/* Auth key: shared label by default; legacy restaurant-log label kept for migration */
async function deriveAuth(pass,saltB64,label){label=label||AUTH_LABEL;var base=await C.subtle.importKey("raw",new TextEncoder().encode(pass),"PBKDF2",false,["deriveBits"]);
 var bits=await C.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:new TextEncoder().encode(label+saltB64),iterations:ITER},base,256);return b2a(bits)}
async function deriveAuthBundle(pass,saltB64){
  var authKey=await deriveAuth(pass,saltB64,AUTH_LABEL), legacyAuthKeys=[];
  for(var i=0;i<LEGACY_LABELS.length;i++) legacyAuthKeys.push(await deriveAuth(pass,saltB64,LEGACY_LABELS[i]));
  return {authKey:authKey,legacyAuthKeys:legacyAuthKeys,upgradeAuthKey:authKey};
}
function newSalt(){return b2a(C.getRandomValues(new Uint8Array(16)))}
function normUser(u){return String(u||"").normalize("NFKC").trim().toLowerCase()}
function forgetPasswords(){KC={}}
function validDate(value){if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(value))return false;var date=new Date(value+"T12:00:00Z");return Number.isFinite(date.getTime())&&date.toISOString().slice(0,10)===value}
var KINDS={ramen:1,cafe:1,burger:1,dessert:1,sushi:1,pasta:1,matcha:1,shop:1,cat:1,taco:1};
function validDb(d){if(!d||d.version!==1||!Array.isArray(d.restaurants)||!Array.isArray(d.visits)||d.restaurants.length>5000||d.visits.length>20000)return false;
 var ids=new Set();for(var i=0;i<d.restaurants.length;i++){var r=d.restaurants[i];
  if(typeof r.id!=="string"||!/^[-\w]+$/.test(r.id)||ids.has(r.id)||typeof r.name!=="string"||!r.name.trim()||r.name.length>100||!Array.isArray(r.tags)||r.tags.length>30||r.tags.some(function(t){return typeof t!=="string"||t.length>150})||typeof r.note!=="string"||typeof r.address!=="string"||typeof r.added!=="string"||!validDate(r.added)||typeof r.wish!=="boolean"||!KINDS[r.kind]||(r.lat===null)!==(r.lng===null)||!(r.lat===null||Number.isFinite(r.lat)&&Math.abs(r.lat)<=90)||!(r.lng===null||Number.isFinite(r.lng)&&Math.abs(r.lng)<=180)||!(r.rating===null||r.rating===undefined||Number.isFinite(r.rating)&&r.rating>=1&&r.rating<=5))return false;ids.add(r.id)}
 var vids=new Set();for(var j=0;j<d.visits.length;j++){var v=d.visits[j];
  if(typeof v.id!=="string"||!/^[-\w]+$/.test(v.id)||vids.has(v.id)||!ids.has(v.restaurantId)||!validDate(v.date)||typeof v.time!=="string"||!/^([01]\d|2[0-3]):[0-5]\d$/.test(v.time)||typeof v.note!=="string"||typeof v.meal!=="string"||!Number.isFinite(v.rating)||v.rating<1||v.rating>5||!Array.isArray(v.photos)||v.photos.length>3||v.photos.some(function(p){return typeof p!=="string"||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p)}))return false;vids.add(v.id)}
 return true}
function mergeById(a,b,key){var map={};(a||[]).concat(b||[]).forEach(function(x){var c=map[x[key]];if(!c||(x.u||0)>=(c.u||0))map[x[key]]=x});return Object.keys(map).map(function(k){return map[k]})}
function merge(local,remote){
 var out=JSON.parse(JSON.stringify(remote));
 out.restaurants=mergeById(local.restaurants,remote.restaurants,"id");
 out.visits=mergeById(local.visits,remote.visits,"id");
 if((local.u||0)>(remote.u||0)){out.profile=local.profile;if("avatar" in local)out.avatar=local.avatar;out.u=local.u}else out.u=Math.max(local.u||0,remote.u||0);
 var del={};[local.del||{},remote.del||{}].forEach(function(m){Object.keys(m).forEach(function(id){del[id]=Math.max(del[id]||0,m[id])})});
 if(Object.keys(del).length){out.del=del;out.restaurants=out.restaurants.filter(function(r){return !(del["r:"+r.id]>=(r.u||0))});out.visits=out.visits.filter(function(v){return !(del["v:"+v.id]>=(v.u||0))&&!del["r:"+v.restaurantId]})}
 return out}
function migrate(db){if(!db.u)db.u=Date.now();(db.restaurants||[]).forEach(function(r){if(r.u==null)r.u=0});(db.visits||[]).forEach(function(v){if(v.u==null)v.u=0});return db}
function hm(ts){return new Intl.DateTimeFormat("en-GB",{hour:"2-digit",minute:"2-digit",hour12:false}).format(new Date(ts))}
var API={ITER:ITER,AUTH_LABEL:AUTH_LABEL,LEGACY_LABELS:LEGACY_LABELS,uid:uid,today:today,defaults:defaults,deriveKey:deriveKey,encrypt:encrypt,decrypt:decrypt,deriveAuth:deriveAuth,deriveAuthBundle:deriveAuthBundle,newSalt:newSalt,normUser:normUser,forgetPasswords:forgetPasswords,validDb:validDb,validDate:validDate,merge:merge,migrate:migrate,hm:hm};
if(typeof module!=="undefined"&&module.exports)module.exports=API;else root.RL=API;
})(typeof globalThis!=="undefined"?globalThis:this);
