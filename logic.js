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
// ui20261015dc: any food/icon kind the app can produce (food keys + icon/<set>/<file>) is valid
function validKind(k){return typeof k==="string"&&k.length<=200&&/^[\w\-\/.]+$/.test(k)}
function validDb(d){if(!d||d.version!==1||!Array.isArray(d.restaurants)||!Array.isArray(d.visits)||d.restaurants.length>5000||d.visits.length>20000)return false;
 var ids=new Set();for(var i=0;i<d.restaurants.length;i++){var r=d.restaurants[i];
  if(typeof r.id!=="string"||!/^[-\w]+$/.test(r.id)||ids.has(r.id)||typeof r.name!=="string"||!r.name.trim()||r.name.length>300||!Array.isArray(r.tags)||r.tags.length>30||r.tags.some(function(t){return typeof t!=="string"||t.length>150})||typeof r.note!=="string"||typeof r.address!=="string"||typeof r.added!=="string"||!validDate(r.added)||typeof r.wish!=="boolean"||!validKind(r.kind)||(r.lat===null)!==(r.lng===null)||!(r.lat===null||Number.isFinite(r.lat)&&Math.abs(r.lat)<=90)||!(r.lng===null||Number.isFinite(r.lng)&&Math.abs(r.lng)<=180)||!(r.rating===null||r.rating===undefined||Number.isFinite(r.rating)&&r.rating>=1&&r.rating<=5))return false;ids.add(r.id)}
 var vids=new Set();for(var j=0;j<d.visits.length;j++){var v=d.visits[j];
  if(typeof v.id!=="string"||!/^[-\w]+$/.test(v.id)||vids.has(v.id)||!ids.has(v.restaurantId)||!validDate(v.date)||typeof v.time!=="string"||(v.time!==""&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(v.time))||typeof v.note!=="string"||typeof v.meal!=="string"||(v.rating!=null&&v.rating!==0&&(!Number.isFinite(v.rating)||v.rating<1||v.rating>5))||!Array.isArray(v.photos)||v.photos.length>3||v.photos.some(function(p){return typeof p!=="string"||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p)}))return false;vids.add(v.id)}
 if(d.pendingGo!==undefined){if(!Array.isArray(d.pendingGo)||d.pendingGo.length>500)return false;var pids=new Set();for(var k=0;k<d.pendingGo.length;k++){var p=d.pendingGo[k];if(!p||typeof p.id!=="string"||!/^[-\w]+$/.test(p.id)||pids.has(p.id)||typeof p.name!=="string"||!p.name.trim()||p.name.length>300||typeof p.address!=="string"||p.address.length>500||!validDate(p.date)||typeof p.meal!=="string"||p.meal.length>40||typeof p.time!=="string"||(p.time!==""&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(p.time))||!(p.lat==null||Number.isFinite(p.lat)&&Math.abs(p.lat)<=90)||!(p.lng==null||Number.isFinite(p.lng)&&Math.abs(p.lng)<=180)||(p.restaurantId!=null&&typeof p.restaurantId!=="string")||(p.sourceId!=null&&(typeof p.sourceId!=="string"||p.sourceId.length>300))||(p.kind!=null&&!validKind(p.kind)))return false;pids.add(p.id)}}
 return true}
function mergeById(a,b,key){var map={};(a||[]).concat(b||[]).forEach(function(x){var c=map[x[key]];if(!c||(x.u||0)>=(c.u||0))map[x[key]]=x});return Object.keys(map).map(function(k){return map[k]})}
function merge(local,remote){
 var out=JSON.parse(JSON.stringify(remote));
 out.restaurants=mergeById(local.restaurants,remote.restaurants,"id");
 out.visits=mergeById(local.visits,remote.visits,"id");
 if(local.pendingGo||remote.pendingGo)out.pendingGo=mergeById(local.pendingGo,remote.pendingGo,"id");
 if((local.u||0)>(remote.u||0)){out.profile=local.profile;if("avatar" in local)out.avatar=local.avatar;out.u=local.u}else out.u=Math.max(local.u||0,remote.u||0);
 var del={};[local.del||{},remote.del||{}].forEach(function(m){Object.keys(m).forEach(function(id){del[id]=Math.max(del[id]||0,m[id])})});
 if(Object.keys(del).length){out.del=del;out.restaurants=out.restaurants.filter(function(r){return !(del["r:"+r.id]>=(r.u||0))});out.visits=out.visits.filter(function(v){return !(del["v:"+v.id]>=(v.u||0))&&!del["r:"+v.restaurantId]});if(out.pendingGo)out.pendingGo=out.pendingGo.filter(function(p){return !(del["p:"+p.id]>=(p.u||0))})}
 if(local.share||remote.share)out.share=mergeShare(local.share,remote.share);
 return out}
function migrate(db){if(!db.u)db.u=Date.now();(db.restaurants||[]).forEach(function(r){if(r.u==null)r.u=0});(db.visits||[]).forEach(function(v){if(v.u==null)v.u=0});return db}

/* ui20261015dz: shared wishlists — E2E. Each user has an ECDH P-256 key pair (private JWK lives only inside the encrypted journal).
   Owner: random AES-256 wishlist key Kw encrypts {places} (AAD = owner); Kw is wrapped per viewer with
   AES-GCM(HKDF-SHA256(ECDH(owner.priv, viewer.pub), salt "meowsto-share/v1", info "owner|viewer")). Server sees ciphertext only. */
var SHARE_FIELDS=["id","name","lat","lng","address","kind","tags","cuisine","sourceId"];
var TE=function(s){return new TextEncoder().encode(s)};
async function shareGenKeys(){var kp=await C.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 var pub=await C.subtle.exportKey("jwk",kp.publicKey),priv=await C.subtle.exportKey("jwk",kp.privateKey);
 return {pub:{kty:"EC",crv:"P-256",x:pub.x,y:pub.y},priv:{kty:"EC",crv:"P-256",x:priv.x,y:priv.y,d:priv.d},c:Date.now()}}
function shareNewWk(){return b2a(C.getRandomValues(new Uint8Array(32)))}
async function pairKey(privJwk,pubJwk,owner,viewer){
 var pk=await C.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:privJwk.x,y:privJwk.y,d:privJwk.d},{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
 var pu=await C.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:pubJwk.x,y:pubJwk.y},{name:"ECDH",namedCurve:"P-256"},false,[]);
 var bits=await C.subtle.deriveBits({name:"ECDH",public:pu},pk,256);
 var hk=await C.subtle.importKey("raw",bits,"HKDF",false,["deriveKey"]);
 return C.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:TE("meowsto-share/v1"),info:TE(owner+"|"+viewer)},hk,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
function sharePlaces(restaurants){return (restaurants||[]).filter(function(r){return r&&r.wish}).map(function(r){var o={};SHARE_FIELDS.forEach(function(k){if(r[k]!==undefined&&r[k]!==null)o[k]=r[k]});return o})}
async function shareSeal(places,owner,wkB64,ownerPriv,viewers){
 var wk=await C.subtle.importKey("raw",a2b(wkB64),{name:"AES-GCM"},false,["encrypt"]),iv=C.getRandomValues(new Uint8Array(12));
 var ct=await C.subtle.encrypt({name:"AES-GCM",iv:iv,additionalData:TE(owner)},wk,TE(JSON.stringify({v:1,owner:owner,places:places})));
 var wraps={};for(var v in viewers){var k=await pairKey(ownerPriv,viewers[v],owner,v),wiv=C.getRandomValues(new Uint8Array(12));
  wraps[v]={iv:b2a(wiv),ct:b2a(await C.subtle.encrypt({name:"AES-GCM",iv:wiv,additionalData:TE(owner+"|"+v)},k,a2b(wkB64)))}}
 return {iv:b2a(iv),ct:b2a(ct),wraps:wraps}}
async function shareOpen(item,myPriv,me){
 var k=await pairKey(myPriv,item.ownerJwk,item.owner,me);
 var raw=await C.subtle.decrypt({name:"AES-GCM",iv:a2b(item.wrap.iv),additionalData:TE(item.owner+"|"+me)},k,a2b(item.wrap.ct));
 var wk=await C.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["decrypt"]);
 var pt=await C.subtle.decrypt({name:"AES-GCM",iv:a2b(item.iv),additionalData:TE(item.owner)},wk,a2b(item.ct));
 var o=JSON.parse(new TextDecoder().decode(pt));if(!o||o.owner!==item.owner||!Array.isArray(o.places))throw new Error("bad share");
 return o.places.filter(function(p){return p&&typeof p.name==="string"&&p.name.trim()&&p.name.length<=300&&typeof p.id==="string"&&/^[-\w]+$/.test(p.id)}).map(function(p){var q={};SHARE_FIELDS.forEach(function(k){if(p[k]!==undefined)q[k]=p[k]});
  q.lat=Number.isFinite(q.lat)&&Math.abs(q.lat)<=90?q.lat:null;q.lng=Number.isFinite(q.lng)&&Math.abs(q.lng)<=180?q.lng:null;if(q.lat===null||q.lng===null){q.lat=null;q.lng=null}
  q.address=typeof q.address==="string"?q.address.slice(0,500):"";q.kind=validKind(q.kind)?q.kind:"shop";q.tags=Array.isArray(q.tags)?q.tags.filter(function(t){return typeof t==="string"&&t.length<=150}).slice(0,30):[];
  if(q.cuisine!==undefined&&typeof q.cuisine!=="string")delete q.cuisine;if(q.sourceId!==undefined&&typeof q.sourceId!=="string")delete q.sourceId;return q})}
function mergeShare(l,r){if(!l)return r;if(!r)return l;var out=JSON.parse(JSON.stringify((l.u||0)>(r.u||0)?l:r));
 // the key pair converges on the oldest one so both devices end up publishing the same public key
 var lk=l.keys,rk=r.keys;if(lk&&rk)out.keys=(lk.c||0)<=(rk.c||0)?lk:rk;else out.keys=lk||rk;return out}
function hm(ts){return new Intl.DateTimeFormat("en-GB",{hour:"2-digit",minute:"2-digit",hour12:false}).format(new Date(ts))}
var API={ITER:ITER,AUTH_LABEL:AUTH_LABEL,LEGACY_LABELS:LEGACY_LABELS,uid:uid,today:today,defaults:defaults,deriveKey:deriveKey,encrypt:encrypt,decrypt:decrypt,deriveAuth:deriveAuth,deriveAuthBundle:deriveAuthBundle,newSalt:newSalt,normUser:normUser,forgetPasswords:forgetPasswords,validDb:validDb,validDate:validDate,merge:merge,migrate:migrate,hm:hm,shareGenKeys:shareGenKeys,shareNewWk:shareNewWk,sharePlaces:sharePlaces,shareSeal:shareSeal,shareOpen:shareOpen,mergeShare:mergeShare,SHARE_FIELDS:SHARE_FIELDS};
if(typeof module!=="undefined"&&module.exports)module.exports=API;else root.RL=API;
})(typeof globalThis!=="undefined"?globalThis:this);
