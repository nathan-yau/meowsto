'use strict';
/* Meowsto — encrypted multi-user client */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>RL.uid(), today=()=>RL.today(), LEGACY_KEY='restaurant-log-v1';
/* Shared auth site — account endpoints only; encrypted data stays on this origin */
const AUTH_ORIGIN=(typeof location!=='undefined'&&/^localhost$|^127\.0\.0\.1$/.test(location.hostname))
  ? (localStorage.getItem('rl.authOrigin')||'https://shared-auth-nshyau.netlify.app')
  : 'https://shared-auth-nshyau.netlify.app';
const DATA_ORIGIN=(typeof location!=='undefined'&&/\.github\.io$/.test(location.hostname))?'https://wonderful-parfait-18a140.netlify.app':'';
const AUTH_PATHS=new Set(['params','register','login','refresh','logout','password','account']);
const DEFAULT_CENTER=[49.2827,-123.1207], DEFAULT_ZOOM=13;
/* Public Mapbox token — Search Box only (basemap stays Leaflet/MapLibre/OSM) */
const MAPBOX_TOKEN='pk.eyJ1IjoibmF0aGFueWF1IiwiYSI6ImNtdjl1eW53YjA4ZWQyd3EwMzJ3ZHQ5d3QifQ.wfFv9UcvOOqXlUX__A0Lrg';
const artIndex={ramen:0,cafe:1,burger:2,dessert:3,sushi:4,pasta:5,matcha:6,shop:7,cat:8,taco:7};
function art(kind='shop'){let n=artIndex[kind]??7;return `<span class="illustration" style="--x:${n%3*50}%;--y:${Math.floor(n/3)*50}%" aria-hidden="true"></span>`}
function icon(type){const paths={map:'<path d="M3 5 9 2l6 3 6-3v17l-6 3-6-3-6 3Z"/><path d="M9 2v17M15 5v17"/>',calendar:'<rect x="3" y="5" width="18" height="17" rx="3"/><path d="M7 2v6M17 2v6M3 11h18"/>',heart:'<path d="M12 21S2 15 2 8a5 5 0 0 1 10-2A5 5 0 0 1 22 8c0 7-10 13-10 13Z"/>',bookmark:'<path d="M6 3h12a1 1 0 0 1 1 1v18l-7-5-7 5V4a1 1 0 0 1 1-1Z"/>',search:'<circle cx="10" cy="10" r="7"/><path d="m15 15 7 7"/>',pin:'<path d="M12 22s7-6.6 7-12a7 7 0 0 0-14 0c0 5.4 7 12 7 12Z"/><circle cx="12" cy="10" r="2.5"/>',sparkle:'<path d="M12 2c.8 5.2 2.8 7.2 8 8-5.2.8-7.2 2.8-8 8-.8-5.2-2.8-7.2-8-8 5.2-.8 7.2-2.8 8-8Z"/>',chev:'<path d="m7 10 5 5 5-5"/>',arrow:'<path d="M5 12h14M13 6l6 6-6 6"/>',plus:'<path d="M12 5v14M5 12h14"/>',note:'<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>',users:'<circle cx="9" cy="8" r="3"/><path d="M3 20c.8-3.5 3.2-5.5 6-5.5s5.2 2 6 5.5"/><path d="M16 5.5a3 3 0 0 1 0 5.5M18 14.8c1.6.8 2.6 2.6 3 5.2"/>'};return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${paths[type]||paths.bookmark}</svg>`}

/* ---------- auth / sync ---------- */
let PASS=null,TOK=null,USER=null,ETAG=null,SALT=null,REFRESH=null,dirty=false,saving=false,tmr=null,MODE='login';
let REMEMBER=localStorage.getItem('rl.remember')!=='0';
function K(n){return 'rl.u.'+USER+'.'+n}
function sync(m){/* sync status intentionally not shown in UI */}
const ERR={'bad credentials':'Wrong username or password','locked':'Too many attempts — try again in 15 minutes','username taken':'That username is taken','bad invite code':'Invalid invite code','bad username':'Username must be 3–32 letters, numbers, or _ . -','offline':'Can’t reach the server'};
function errMsg(j){return ERR[j.error]||j.error||('HTTP '+j._s)}
async function api(path,method,body,noAuth){const h={'Content-Type':'application/json'};if(TOK&&!noAuth)h.Authorization='Bearer '+TOK;
  const base=AUTH_PATHS.has(path)?AUTH_ORIGIN:DATA_ORIGIN;
  let r;try{r=await fetch(base+'/api/'+path,{method,cache:'no-store',headers:h,body:body&&JSON.stringify(body)})}catch(e){return {_s:0,error:'offline'}}
  const j=await r.json().catch(()=>({}));j._s=r.status;return j}
function idb(){return new Promise((res,rej)=>{const r=indexedDB.open('rl-vault',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)})}
async function vault(op,val){try{const db=await idb();return await new Promise((res,rej)=>{const tx=db.transaction('k',op==='get'?'readonly':'readwrite'),st=tx.objectStore('k'),q=op==='get'?st.get('cur'):op==='put'?st.put(val,'cur'):st.delete('cur');q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error)})}catch(e){return null}}
async function keep(){if(REMEMBER&&REFRESH&&typeof PASS!=='string')await vault('put',{user:USER,salt:SALT,key:PASS,refresh:REFRESH})}
async function toKey(p,salt){const k=await RL.deriveKey(p,salt,RL.ITER);RL.forgetPasswords();return k}
function cacheEnv(env,etag){localStorage.setItem(K('env'),JSON.stringify(env));if(etag!==undefined)localStorage.setItem(K('etag'),etag||'')}
function lockMsg(m,bad){const x=$('#umsg');x.className='umsg'+(bad?' bad':'');x.textContent=m}
function setMode(m){MODE=m;const reg=m==='reg';document.body.classList.toggle('reg-mode',reg);$$('#lmode button').forEach(b=>{const on=b.dataset.m===m;b.classList.toggle('on',on);b.setAttribute('aria-selected',on?'true':'false')});$('#go').textContent=reg?'Sign up →':'Log in →';$('#pw').autocomplete=reg?'new-password':'current-password';const sf=$('#signup-fields');if(sf){sf.setAttribute('aria-hidden',reg?'false':'true');$$('#signup-fields input').forEach(el=>{el.tabIndex=reg?0:-1})}lockMsg('')}
async function doLogin(u,p){const name=RL.normUser(u),pr=await api('params','POST',{username:name},true);if(pr._s!==200)throw new Error(errMsg(pr));
  const b=await RL.deriveAuthBundle(p,pr.salt);
  const j=await api('login','POST',{username:name,authKey:b.authKey,legacyAuthKeys:b.legacyAuthKeys,upgradeAuthKey:b.upgradeAuthKey,remember:REMEMBER},true);if(j._s!==200)throw new Error(errMsg(j));
  USER=j.username;TOK=j.token;SALT=j.salt;PASS=await toKey(p,SALT);REFRESH=j.refresh||null;localStorage.setItem('rl.lastUser',USER);await keep();await loadData()}
async function doRegister(u,p,code){const name=RL.normUser(u),salt=RL.newSalt();
  let db=RL.defaults();
  // Migrate legacy local-only journal into first encrypted blob
  try{const raw=localStorage.getItem(LEGACY_KEY);if(raw){const legacy=JSON.parse(raw);if(RL.validDb(legacy)){db=RL.migrate(legacy);localStorage.setItem(LEGACY_KEY+'-migrated-at',String(Date.now()))}}}catch{}
  const ak=await RL.deriveAuth(p,salt);
  // Account on shared-auth (no env); encrypted journal stays on this site
  const j=await api('register','POST',{username:name,salt,authKey:ak,code,remember:REMEMBER},true);if(j._s!==200)throw new Error(errMsg(j));
  USER=j.username;TOK=j.token;SALT=salt;PASS=await toKey(p,SALT);REFRESH=j.refresh||null;localStorage.setItem('rl.lastUser',USER);await keep();localStorage.removeItem(K('env'));
  state=db;dirty=true;await loadData()}
async function tryRefresh(){if(!REFRESH)return false;const j=await api('refresh','POST',{refresh:REFRESH},true);if(j._s!==200){if(j._s===401){REFRESH=null;await vault('del');return false}return 'off'}TOK=j.token;REFRESH=j.refresh;await keep();return true}
function expired(){TOK=null;PASS=null;$('#un').value=USER||localStorage.getItem('rl.lastUser')||'';document.body.classList.add('locked');$('#app').hidden=true;lockMsg('Session expired — please log in again (unsynced changes are still on this device)',true)}
async function loadData(){let cached=localStorage.getItem(K('env')),local=null;
  if(cached){try{const ce=JSON.parse(cached);if(ce.salt===SALT)local=await RL.decrypt(ce,PASS)}catch(e){local=null}ETAG=localStorage.getItem(K('etag'))||null;dirty=!!localStorage.getItem(K('dirty'))}
  if(local){state=RL.migrate(local);bootApp();sync('Loaded encrypted local copy…')}
  const j=await api('data','GET');
  if(j._s===401){if(await tryRefresh()===true)return loadData();return expired()}
  if(j._s!==200){if(!local){if(j._s)throw new Error(errMsg(j));state=RL.defaults();bootApp()}sync('Can’t sync right now — saved on this device');return}
  if(j.empty){
    // First login: migrate legacy localStorage if present
    if(!local){let db=RL.defaults();try{const raw=localStorage.getItem(LEGACY_KEY);if(raw){const legacy=JSON.parse(raw);if(RL.validDb(legacy)){db=RL.migrate(legacy);localStorage.setItem(LEGACY_KEY+'-migrated-at',String(Date.now()))}}}catch{}state=db;bootApp()}
    dirty=true;save();return}
  if(j.etag!==ETAG||!local){const remote=await RL.decrypt(j.env,PASS);state=(local&&dirty)?RL.merge(local,remote):RL.migrate(remote);ETAG=j.etag;if(!dirty)cacheEnv(j.env,j.etag);if(!local)bootApp();else render()}
  sync(dirty?'Unsynced changes…':'Synced ✓');if(dirty)save()}
async function save(){if(!TOK)return false;if(saving){clearTimeout(tmr);tmr=setTimeout(save,800);return}saving=true;
  try{const env=await RL.encrypt(state,PASS,SALT);cacheEnv(env);
    for(let i=0;i<4;i++){const j=await api('data','PUT',{env,etag:ETAG});
      if(j._s===200){ETAG=j.etag;cacheEnv(env,ETAG);dirty=false;localStorage.removeItem(K('dirty'));sync('Synced ✓ '+RL.hm(Date.now()));return true}
      if(j._s===409&&j.env){state=RL.merge(state,await RL.decrypt(j.env,PASS));ETAG=j.etag;const env2=await RL.encrypt(state,PASS,SALT);cacheEnv(env2);render();continue}
      if(j._s===401){const tr=await tryRefresh();if(tr===true)continue;if(tr==='off'){sync('Can’t sync right now — saved on this device');return false}expired();return false}
      sync('Can’t sync right now — saved on this device');return false}
    sync('Can’t sync right now — saved on this device');return false}
  catch(e){sync('Can’t sync right now — saved on this device');return false}finally{saving=false}}
function markDirty(){state.u=Date.now();dirty=true;localStorage.setItem(K('dirty'),'1');clearTimeout(tmr);tmr=setTimeout(save,1200);sync('Saving…')}
async function doLogout(){if(dirty&&!(await save())&&!confirm('Some changes haven’t synced yet (they’re encrypted on this device). Log out anyway?'))return;
  await api('logout','POST',{refresh:REFRESH});await vault('del');REFRESH=null;location.reload()}
window.addEventListener('online',()=>{if(dirty)save()});

/* ---------- journal state ---------- */
function initial(){return RL.defaults()}
function removeLegacySamples(data){
  const d=structuredClone(data), sampleIds=new Set(d.restaurants.filter(r=>r.demo).map(r=>r.id));
  d.visits=d.visits.filter(v=>!(sampleIds.has(v.restaurantId)&&/^visit-\d+$/.test(v.id)));
  const used=new Set(d.visits.map(v=>v.restaurantId));
  d.restaurants=d.restaurants.filter(r=>!r.demo||used.has(r.id)).map(r=>{
    if(!r.demo)return r;
    return {...r,demo:false,lat:null,lng:null,address:'',rating:null,note:'',tags:[]};
  });
  return d;
}
let state=initial(), recoveryRequired=false, recoveryRaw=null;
let tab='map',selected=null,filter='All',sort='newest',map,baseLayer,mapSizeObserver,markers=[],searchMarkers=[],userLocation,searchTimer,searchBusy=false,searchResults=[],mapCenter=[...DEFAULT_CENTER],mapZoom=DEFAULT_ZOOM,searchContext={},pendingVisit=false;
const HIDE_VISITED_KEY='meowsto-hide-visited';
let hideVisited=localStorage.getItem(HIDE_VISITED_KEY)==='1',lastSearchQuery='';
function syncHideVisitedChip(){
  const el=document.querySelector('.map-hide-visited');
  if(!el)return;
  const searching=!!document.querySelector('#sheet .search-sheet')||searchResults.length>0;
  el.hidden=!searching;
  const cb=el.querySelector('[data-hide-visited]');
  if(cb)cb.checked=hideVisited;
}
let listPage=0, PAGE_SIZE=4, panelMode='sheet', expandedVisitId=null;
const rest=id=>state.restaurants.find(r=>r.id===id), visits=id=>state.visits.filter(v=>v.restaurantId===id).sort((a,b)=>(b.date+b.time).localeCompare(a.date+a.time));
function validBackup(d){return RL.validDb(d)}
function persist(){if(!USER)return false;try{markDirty();const envPlaceholder=true;cacheEnv;return true}catch{toast('Save failed');return false}}
function commit(change){
  const prev=structuredClone(state);
  {const used=new Set(state.visits.map(v=>v.restaurantId));state.restaurants=state.restaurants.filter(r=>!(r.demo&&!r.preview&&/^demo-\d$/.test(r.id)&&!used.has(r.id)))}
  try{
    change();
    if(!validBackup(state))throw Error('Please check the name, date, time, and rating.');
    (state.restaurants||[]).forEach(r=>{if(r.u==null)r.u=Date.now()});
    (state.visits||[]).forEach(v=>{if(v.u==null)v.u=Date.now()});
    markDirty();
    return true;
  }catch(err){state=prev;toast(err.message||'Save failed — your previous data is safe.');return false}
}
function toast(s){const t=$('#toast');t.textContent=s;t.classList.add('show');clearTimeout(searchTimer);searchTimer=setTimeout(()=>t.classList.remove('show'),4000)}
function fmt(d){return d?d.slice(5).replace('-','/'):'—'}
function relativeVisitLabel(dateStr){
  if(!dateStr||!/^\d{4}-\d{2}-\d{2}$/.test(dateStr))return '';
  const now=new Date(), visit=new Date(dateStr+'T12:00:00');
  if(!Number.isFinite(visit.getTime()))return '';
  const startToday=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const startVisit=new Date(visit.getFullYear(),visit.getMonth(),visit.getDate());
  const diffDays=Math.round((startToday-startVisit)/86400000);
  if(diffDays<=0)return 'today';
  if(diffDays===1)return 'yesterday';
  if(diffDays<7)return 'this week';
  if(diffDays<14)return 'last week';
  if(now.getFullYear()===visit.getFullYear()&&now.getMonth()===visit.getMonth())return 'this month';
  const months=(now.getFullYear()-visit.getFullYear())*12+(now.getMonth()-visit.getMonth());
  if(months===1)return 'last month';
  if(months<12)return months+' months ago';
  if(months<24)return 'last year';
  return Math.floor(months/12)+' years ago';
}
function tags(r){return `<div class="tags">${(r.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div>`}
function personalRating(r){const rated=visits(r.id).filter(v=>v.rating);return rated.length?Math.round(rated.reduce((sum,v)=>sum+v.rating,0)/rated.length*10)/10:r.rating}
function rating(r){const value=personalRating(r);return value?`<div class="rating"><span class="star">★</span> ${value} <small>· your rating</small></div>`:''}
function tile(r){const photo=visits(r.id).find(v=>v.photos?.length)?.photos[0];return `<div class="food-tile ${esc(r.kind)}">${photo?`<img class="restaurant-photo" src="${photo}" alt="Your photo of ${esc(r.name)}">`:art(r.kind)}</div>`}

/* ---------- panels (no <dialog>) ---------- */
function openPanel(title,html,opts={}){
  destroyPlacePreview();if(activeSearch)cancelSearch();
  const panel=$('#panel');panel.hidden=false;panel.className='panel open'+(opts.full?' full':'')+(opts.cls?' '+opts.cls:'');
  panel.setAttribute('aria-hidden','false');
  $('#panel-title').textContent=title;
  $('#modal').innerHTML=html;
  enhanceIcons();
  panelMode=opts.full?'full':'sheet';
}
function closePanel(){destroyPlacePreview();cancelSearch();const panel=$('#panel');panel.hidden=true;panel.className='panel';panel.setAttribute('aria-hidden','true');$('#modal').innerHTML='';pendingVisit=false}
function closeModal(){closePanel()}
function openModal(title,html){openPanel(title,html,{full:true,cls:'entry-panel'})}

function enhanceIcons(){
  $$('.tabs button').forEach(b=>{const key=b.dataset.tab;b.innerHTML=icon({map:'map',timeline:'calendar',wishlist:'heart'}[key])+`<span>${key[0].toUpperCase()+key.slice(1)}</span>`});
  $$('.save').forEach(b=>{b.classList.toggle('saved',!!rest(b.dataset.save)?.wish);b.innerHTML=icon('bookmark')});
  
  $$('#bnav [data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
}

function render(){
  mapSizeObserver?.disconnect();
  if(map){mapCenter=[map.getCenter().lat,map.getCenter().lng];mapZoom=map.getZoom();map.remove();map=null}
  $$('[data-tab]').forEach(b=>{const on=b.dataset.tab===tab;b.classList.toggle('active',on);b.setAttribute('aria-pressed',String(on))});
  $('#main').className='view-'+tab+(tab==='timeline'?' timeline':'');
  listPage=0;
  if(tab==='map')renderMap();else if(tab==='timeline')renderTimeline();else renderWishlist();
  enhanceIcons();
}

function pageSlice(rows){const pages=Math.max(1,Math.ceil(rows.length/PAGE_SIZE));listPage=Math.min(listPage,pages-1);const slice=rows.slice(listPage*PAGE_SIZE,(listPage+1)*PAGE_SIZE);return {slice,pages,total:rows.length}}
function pagerHtml(pages,total,label){if(total<=PAGE_SIZE)return '';return `<div class="list-pager"><button type="button" data-page="prev" ${listPage<=0?'disabled':''}>‹ Prev</button><span class="page-info">${label||''} ${listPage+1}/${pages}</span><button type="button" data-page="next" ${listPage>=pages-1?'disabled':''}>Next ›</button></div>`}

function card(r){const vv=visits(r.id);return `<article class="restaurant no-tile"><div class="info" role="button" tabindex="0" data-detail="${r.id}"><h3>${esc(r.name)}</h3>${rating(r)}<p class="visit-meta">♜ ${vv.length} visit${vv.length===1?'':'s'}${vv[0]?` · last ${fmt(vv[0].date)}`:''}</p><p class="address">♧ ${esc(r.address||'Location not added')}</p>${tags(r)}<p class="note">▤ ${esc(r.note||'Add a little note…')}</p></div><div class="right-meta"><button class="save" data-save="${r.id}" aria-label="${r.wish?'Remove from':'Add to'} wishlist">${r.wish?'▮':'♧'}</button></div><button class="chevron" data-detail="${r.id}" aria-label="Open ${esc(r.name)}">›</button></article>`}

function renderWishlist(){
  let rows=state.restaurants.filter(r=>r.wish&&(filter==='All'||r.tags.some(t=>t.toLowerCase()===filter.toLowerCase())));
  rows.sort((a,b)=>sort==='rating'?(personalRating(b)||0)-(personalRating(a)||0):sort==='name'?a.name.localeCompare(b.name):b.added.localeCompare(a.added));
  const {slice,pages,total}=pageSlice(rows);
  const chips=['All',...new Set(['Ramen','Cafe','Japanese','Dessert',...state.restaurants.filter(r=>r.wish).flatMap(r=>r.tags)])];
  $('#main').innerHTML=`<div class="content"><section class="hero"><div class="art-box">${logo()}</div><div><h2>Places to Try</h2><p>Good food is always<br>a good idea!</p></div><button class="primary" data-action="search-wish">⊕ Add to Wishlist</button></section><div class="filters">${chips.slice(0,6).map(t=>`<button data-filter="${esc(t)}" class="${filter===t?'active':''}">${t==='Ramen'?'🍜 ':t==='Cafe'?'☕ ':''}${esc(t)}</button>`).join('')}${chips.length>6?`<button data-action="more-filters">＋${chips.length-6}</button>`:''}<button data-action="filters" aria-label="Sort wishlist">☷</button></div><div class="restaurant-list" aria-label="Saved restaurants">${total?slice.map(card).join(''):'<div class="empty">A delicious adventure awaits.<br>Add a restaurant to your wishlist!</div>'}</div>${pagerHtml(pages,total,'Wishlist')}</div>`;
}

function renderTimeline(){
  const all=[...state.visits].sort((a,b)=>sort==='oldest'?(a.date+a.time).localeCompare(b.date+b.time):(b.date+b.time).localeCompare(a.date+a.time));
  const latest=[...state.visits].sort((a,b)=>(b.date+b.time).localeCompare(a.date+a.time))[0];
  const r=latest&&rest(latest.restaurantId);
  const miles=all.slice(0,5);
  $('#main').innerHTML=`<div class="content">${miles.length?`<div class="milestones">${miles.map(v=>`<button data-visit="${v.id}"><span class="circle" aria-hidden="true"></span><small>${fmt(v.date)}</small></button>`).join('')}</div>`:''}${r?`<section class="latest no-art" data-detail="${r.id}" role="button" tabindex="0"><div><h2>${esc(r.name)}</h2><span class="badge">Latest visit</span> <span class="latest-rating">★ ${latest.rating}</span></div></section>`:''}<div class="section-title"><h2>All Visits <small>(${all.length})</small></h2><select id="timeline-sort" aria-label="Sort visits"><option value="newest" ${sort!=='oldest'?'selected':''}>Newest First</option><option value="oldest" ${sort==='oldest'?'selected':''}>Oldest First</option></select></div><button class="primary timeline-add" data-action="visit">＋ Add Visit</button><div class="timeline-list" aria-label="Visit history">${all.length?all.map(v=>{const open=expandedVisitId===v.id;return `<div class="visit-row"><div class="visit-date">${fmt(v.date)}<small>${new Date(v.date+'T12:00:00').toLocaleDateString('en-US',{weekday:'short'})}</small></div><div class="visit-card no-art${open?' expanded':''}" data-visit-toggle="${v.id}" role="button" tabindex="0" aria-expanded="${open?'true':'false'}"><div class="visit-card-main"><div class="visit-card-body"><span class="visit-time">${esc(v.time)}</span><span class="meal">${v.meal==='Cafe'?'☕':'♜'} ${esc(v.meal)}</span><h3>${esc(rest(v.restaurantId)?.name||'Restaurant')}</h3></div><span class="chevron" aria-hidden="true">${open?'▴':'▾'}</span></div>${open?visitExpandHtml(v):''}</div></div>`}).join(''):'<div class="empty">Your story starts with a good meal.<br>Log your first visit!</div>'}</div></div>`;
}

function renderMap(){
  $('#main').innerHTML=`<div class="map-wrap"><div class="map-toolbar"><button type="button" data-action="locate" class="chip-near" aria-label="Go to my location">${icon('pin')}<span>Near me</span>${icon('chev')}</button><button type="button" data-action="explore" class="explore-toggle${exploreOn?' active':''}" aria-pressed="${exploreOn}" aria-label="${exploreOn?'Exit explore mode':'Explore nearby restaurants'}">${exploreOn?'✕ <span>Exit</span>':icon('sparkle')+'<span>Explore</span>'+icon('chev')}</button></div><form class="map-search-bar" id="map-search-form" role="search"><span class="map-search-ico" aria-hidden="true">${icon('search')}</span><input id="map-search-query" type="search" enterkeyhint="search" placeholder="Search nearby restaurants" aria-label="Search nearby restaurants" autocomplete="off" maxlength="200"><button type="submit" class="map-search-go" aria-label="Search">${icon('arrow')}</button></form><label class="hide-visited-toggle map-hide-visited" hidden><input type="checkbox" data-hide-visited ${hideVisited?'checked':''}><span>Hide visited</span></label><div id="map" aria-label="Restaurant map"></div>${exploreOn?'<div class="explore-banner">Explore mode · nearby restaurants from OpenStreetMap (not your pins)</div>':''}<div id="map-status" class="map-status" role="status" hidden></div></div><div id="sheet"></div>`;
  if(typeof L==='undefined'||typeof window.L==='undefined'&&typeof leaflet==='undefined'){/* leaflet global is L which conflicts — use window check */}
  if(typeof window.L==='undefined'){$('#map').innerHTML='<div class="failure">The map could not load. Check your connection.<br><button data-action="reload-map">Try again</button></div>';wireMapSearch()}
  else{
    map=window.L.map('map',{zoomControl:false}).setView(mapCenter,mapZoom);
    baseLayer=createMapTiles(map);drawMarkers();
    if(userLocation)window.L.circleMarker(userLocation,{radius:8,color:'#fff',fillColor:'#548ac1',fillOpacity:1}).addTo(map);
  }
  renderSheet();
  enhanceIcons();
  wireMapSearch();
  syncHideVisitedChip();
  if(map&&typeof ResizeObserver!=='undefined'){mapSizeObserver=new ResizeObserver(()=>{if(map)map.invalidateSize({animate:false,debounceMoveend:true})});mapSizeObserver.observe($('#map'))}
}

function createMapTiles(target,statusSelector='#map-status'){
  let layer=null, disposed=false, generation=0;
  const attribution='<a href="https://openfreemap.org/">OpenFreeMap</a> · © <a href="https://openmaptiles.org/">OpenMapTiles</a> · © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';
  function failure(){
    const status=$(statusSelector);if(!status||disposed)return;
    const center=target.getCenter();
    status.innerHTML=`<p>The map could not load. Your saved places and coordinates are safe.</p><div>${statusSelector==='#map-status'?'<button data-action="retry-map">Retry map</button>':''}<a href="https://www.openstreetmap.org/#map=${target.getZoom()}/${center.lat.toFixed(5)}/${center.lng.toFixed(5)}" target="_blank" rel="noopener">Open map ↗</a></div>`;
    status.hidden=false;
  }
  function load(){
    if(disposed)return;
    const attempt=++generation;
    const status=$(statusSelector);if(status)status.hidden=true;
    if(layer){layer.remove();layer=null}
    try{
      if(typeof maplibregl==='undefined'||typeof window.L.maplibreGL!=='function')throw Error('Vector maps unavailable');
      layer=window.L.maplibreGL({style:'assets/quiet-map.json?v=meowsto-cozy2',interactive:false,padding:0.15,attributionControl:false}).addTo(target);
      const gl=layer.getMaplibreMap();
      gl.on('error',()=>{if(attempt===generation)failure()});
      gl.on('idle',()=>{if(attempt===generation&&!disposed&&gl.isStyleLoaded()&&gl.areTilesLoaded()){const status=$(statusSelector);if(status)status.hidden=true}});
    }catch(error){failure()}
  }
  target.once('unload',()=>{disposed=true;generation++});
  load();
  return {redraw:load};
}
let exploreOn=false,exploreLayer=null,exploreTimer,exploreAbort,exploreResults=[],exploreCache={};
function loadExplore(){clearTimeout(exploreTimer);exploreTimer=setTimeout(async()=>{if(!map||!exploreOn)return;if(map.getZoom()<14){showExplore([]);toast('Zoom in to explore nearby places');return}const b=map.getBounds(),bb=[b.getSouth(),b.getWest(),b.getNorth(),b.getEast()].map(x=>x.toFixed(3)).join(',');if(exploreCache[bb])return showExplore(exploreCache[bb]);exploreAbort?.abort();exploreAbort=new AbortController();try{const q=`[out:json][timeout:15];nwr["amenity"~"^(restaurant|fast_food)$"]["name"](${bb});out center 80;`;let j;for(const ep of['https://overpass-api.de/api/interpreter','https://overpass.private.coffee/api/interpreter','https://overpass.kumi.systems/api/interpreter']){try{const res=await fetch(ep,{method:'POST',body:'data='+encodeURIComponent(q),headers:{'Content-Type':'application/x-www-form-urlencoded'},signal:exploreAbort.signal});if(!res.ok)continue;j=await res.json();break}catch(e){if(e.name==='AbortError')throw e}}if(!j)throw Error('overpass');const list=j.elements.map(e=>({name:e.tags.name,lat:e.lat??e.center?.lat,lng:e.lon??e.center?.lon,amenity:e.tags.amenity,cuisine:e.tags.cuisine||'',address:[e.tags['addr:housenumber'],e.tags['addr:street']].filter(Boolean).join(' ')})).filter(x=>Number.isFinite(x.lat));exploreCache[bb]=list;showExplore(list)}catch(err){if(err.name!=='AbortError')toast('Explore data unavailable right now')}},500)}
function showExplore(list){if(exploreLayer)exploreLayer.remove();exploreLayer=window.L.layerGroup().addTo(map);exploreResults=list;list.forEach((x,i)=>{window.L.marker([x.lat,x.lng],{title:x.name,icon:window.L.divIcon({className:'restaurant-pin explore-pin',html:`<div class="map-chip explore-chip"><b>${esc(x.name)}</b></div>`,iconSize:null,iconAnchor:[0,0]})}).bindPopup(`<div class="explore-pop"><b>${esc(x.name)}</b><small>${esc(x.amenity.replace('_',' '))}${x.cuisine?' · '+esc(x.cuisine.replace(/;/g,', ')):''}</small><button data-explore="${i}">♡ Save to wishlist</button></div>`).addTo(exploreLayer)})}
function pinTier(){const z=map?map.getZoom():mapZoom;return z>=14?'full':z>=12?'mini':'meow'}
function searchPinTier(){const z=map?map.getZoom():mapZoom;return z>=16?'full':'meow'}
function markerIcon(r){const t=pinTier(),sel=r.id===selected?' selected':'';if(t==='meow'){const sz=r.id===selected?[30,41]:[22,30];return window.L.icon({iconUrl:'assets/meow-map-pin.png?v=ui20261015x',iconSize:sz,iconAnchor:[sz[0]/2,sz[1]],className:'meow-pin'+sel})}const last=visits(r.id)[0],nv=!last?' never-visited':'';let meta='';if(t==='full'){if(last)meta=relativeVisitLabel(last.date);else meta=r.wish?'♡ never visited':'never visited'}return window.L.divIcon({className:'restaurant-pin pin-'+t,html:`<div class="map-chip${sel}${nv}">${sel?'<i class="pin-burst" aria-hidden="true"></i>':''}<b>${esc(r.name)}</b>${meta?`<small>${esc(meta)}</small>`:''}</div>`,iconSize:null,iconAnchor:[0,0]})}
function updateMarkerIcons(){markers.forEach(m=>m.setIcon(markerIcon(m._r)));searchMarkers.forEach((m,i)=>{if(m&&searchResults[i])m.setIcon(searchResultIcon(searchResults[i],i))})}
function selectPin(id){
  selected=selected===id?null:id;
  updateMarkerIcons();renderSheet();enhanceIcons();
  if(selected&&map){
    const r=rest(selected);
    if(r&&Number.isFinite(r.lat)&&Number.isFinite(r.lng)){
      const z=Math.max(map.getZoom(),15);
      centerMapAboveSheet(r.lat,r.lng,z);
    }
  }
}
let searchFocusIdx=null;
function clearSearchMarkers(){searchMarkers.forEach(m=>m&&m.remove());searchMarkers=[]}
function featureSourceId(p){
  if(!p)return null;
  return p.sourceId||(p.osm_type!=null&&p.osm_id!=null?`${p.osm_type}:${p.osm_id}`:null)||(p.mapbox_id?`mapbox:${p.mapbox_id}`:null);
}
function metersBetween(lat1,lng1,lat2,lng2){
  const rad=x=>x*Math.PI/180,dlat=rad(lat2-lat1),dlng=rad(lng2-lng1);
  const a=Math.sin(dlat/2)**2+Math.cos(rad(lat1))*Math.cos(rad(lat2))*Math.sin(dlng/2)**2;
  return 6371000*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}
const MATCH_NEAR_M=80;
function matchJournalRestaurant(f){
  const p=f?.properties||{},c=f?.geometry?.coordinates;
  const sid=featureSourceId(p);
  if(sid){const byId=state.restaurants.find(r=>r.sourceId===sid);if(byId)return byId}
  const name=String(p.name||p.street||'').trim().toLowerCase();
  if(!name||!Array.isArray(c)||!Number.isFinite(c[0])||!Number.isFinite(c[1]))return null;
  let best=null,bestD=MATCH_NEAR_M;
  for(const r of state.restaurants){
    if(String(r.name||'').trim().toLowerCase()!==name)continue;
    if(!Number.isFinite(r.lat)||!Number.isFinite(r.lng))continue;
    const d=metersBetween(c[1],c[0],r.lat,r.lng);
    if(d<bestD){bestD=d;best=r}
  }
  return best;
}
function searchHitLastVisit(f){
  const r=matchJournalRestaurant(f);if(!r)return null;
  return visits(r.id)[0]||null;
}
function searchHitNameMatchesQuery(f){
  const q=String(lastSearchQuery||'').trim().toLowerCase();
  if(!q)return false;
  const name=String(f?.properties?.name||f?.properties?.street||'').toLowerCase();
  return name.includes(q);
}
function searchHitHidden(f){
  return false; // search results never filtered by visited
  if(!hideVisited)return false;
  if(!searchHitLastVisit(f))return false;
  if(searchHitNameMatchesQuery(f))return false;
  return true;
}
function searchResultIcon(f,i){
  const t=searchPinTier(),sel=searchFocusIdx!=null&&Number(i)===Number(searchFocusIdx);
  if(t==='meow'){
    return window.L.icon({iconUrl:'assets/meow-map-pin-search.png?v=ui20261015ag',iconSize:[24,33],iconAnchor:[12,33],className:'meow-pin meow-pin-search'+(sel?' search-pin-active':'')});
  }
  const name=(f&&f.properties&&(f.properties.name||f.properties.street))||'Place';
  const last=searchHitLastVisit(f);
  const nv=!last?' never-visited':'';
  let meta='never visited';
  if(last)meta=relativeVisitLabel(last.date)||'visited';
  return window.L.divIcon({className:'restaurant-pin pin-'+t,html:`<div class="map-chip${nv}${sel?' selected':''}">${sel?'<i class="pin-burst" aria-hidden="true"></i>':''}<b>${esc(name)}</b>${meta?`<small>${esc(meta)}</small>`:''}</div>`,iconSize:null,iconAnchor:[0,0]});
}
function drawSearchMarkers(){
  clearSearchMarkers();
  if(!map||!searchResults.length)return;
  searchResults.forEach((f,i)=>{
    if(searchHitHidden(f))return;
    const c=f.geometry?.coordinates;if(!c||!Number.isFinite(c[0])||!Number.isFinite(c[1]))return;
    const name=f.properties?.name||'Result';
    const m=window.L.marker([c[1],c[0]],{icon:searchResultIcon(f,i),title:name,riseOnHover:true,zIndexOffset:600,bubblingMouseEvents:false}).addTo(map);
    m.on('click',e=>{window.L.DomEvent.stopPropagation(e);openSearchHitFromPin(i)});
    searchMarkers[i]=m;
  });
}
function drawMarkers(){if(!map)return;markers.forEach(m=>m.remove());markers=[];if(exploreOn){clearSearchMarkers();loadExplore();bindMapEvents();return}state.restaurants.filter(r=>Number.isFinite(r.lat)&&Number.isFinite(r.lng)&&!(hideVisited&&visits(r.id).length)).forEach(r=>{const m=window.L.marker([r.lat,r.lng],{icon:markerIcon(r),title:r.name,riseOnHover:true,bubblingMouseEvents:false}).addTo(map).on('click',e=>{window.L.DomEvent.stopPropagation(e);selectPin(r.id)});m._r=r;markers.push(m)});drawSearchMarkers();bindMapEvents()}
function bindMapEvents(){if(!map._meowZoom){map._meowZoom=1;let last=pinTier(),lastS=searchPinTier();map.on('zoomend',()=>{mapZoom=map.getZoom();const t=pinTier(),s=searchPinTier();if(t!==last||s!==lastS){last=t;lastS=s;updateMarkerIcons()}});map.on('moveend',()=>{const c=map.getCenter();mapCenter=[c.lat,c.lng];if(exploreOn)loadExplore()});map.on('click',()=>{if(selected){selected=null;updateMarkerIcons();renderSheet();enhanceIcons()}})}}
function distance(r){if(!userLocation||!Number.isFinite(r.lat))return '';const rad=x=>x*Math.PI/180,dlat=rad(r.lat-userLocation[0]),dlng=rad(r.lng-userLocation[1]),a=Math.sin(dlat/2)**2+Math.cos(rad(r.lat))*Math.cos(rad(userLocation[0]))*Math.sin(dlng/2)**2;let km=6371*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));return `${km<1?Math.round(km*1000)+' m':km.toFixed(1)+' km'} · `}
function renderSheet(){
  const el=$('#sheet');if(!el)return;
  const r=rest(selected);
  if(!r&&state.restaurants.length){el.innerHTML='';return}
  if(!r){el.innerHTML='<section class="empty onboarding"><div class="onboarding-art">'+logo()+'</div><h2>Your next favorite starts here</h2><p>Find a real restaurant, save it to your map, and make your first food memory.</p><div class="actions"><button class="primary" data-action="search">Find a restaurant</button><button data-action="locate">◎ Use my location</button></div></section>';return}
  selected=r.id;const vv=visits(r.id);
  const pr=personalRating(r);
  el.innerHTML=`<section class="detail-sheet sheet-compact">
    <div class="handle" aria-hidden="true"></div>
    <div class="sheet-head">
      <div class="info">
        <h2>${esc(r.name)}</h2>
        <p class="sheet-sub">${pr?`<span class="sheet-star">★</span> <b>${pr}</b> <span class="sheet-loc">${icon('pin')}</span>`:`<span class="sheet-loc">${icon('pin')}</span>`}${distance(r)}${esc(r.address||'Pinned location')}</p>
        ${tags(r)}
      </div>
      <button type="button" class="save" data-save="${r.id}" aria-label="Toggle wishlist">${r.wish?'▮':'♧'}</button>
    </div>
    <p class="sheet-stats">${icon('users')} ${vv.length} visit${vv.length===1?'':'s'}${vv[0]?` · last ${relativeVisitLabel(vv[0].date)||vv[0].date}`:''}</p>
    <div class="sheet-actions">
      <button type="button" class="secondary" data-addvisit="${r.id}">${icon('plus')} Visit</button>
      <button type="button" data-note="${r.id}">${icon('note')} Note</button>
      <button type="button" class="primary" data-detail="${r.id}">Details ›</button>
    </div>
  </section>`;
  bindSheetDismiss(el.querySelector('.detail-sheet'), ()=>{
    selected=null;updateMarkerIcons();renderSheet();enhanceIcons();
  });
}

function restaurantDetail(id){
  const r=rest(id);if(!r)return;selected=id;
  const vv=visits(id);
  const show=vv.slice(0,3);
  openPanel(r.name,`<div class="form-scroll"><div class="detail-top">${tile(r)}<div>${rating(r)}${tags(r)}<p class="address">${esc(r.address)}</p></div></div><p style="margin-top:10px">${esc(r.note)}</p><a class="link" href="https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(Number.isFinite(r.lat)?r.lat+','+r.lng:r.name+' '+r.address)}" target="_blank" rel="noopener">↗ Google Maps</a><div class="actions"><button class="secondary" data-addvisit="${id}">＋ Add Visit</button><button data-save="${id}">${r.wish?'♥ Saved':'♡ Save'}</button><button data-edit="${id}">Edit</button></div>${Number.isFinite(r.lat)?`<button class="map-view-button" data-map="${id}">◎ Show on map</button>`:`<p class="hint">Add location to see a pin.</p>`}<h3 style="margin-top:12px">Visits (${vv.length})</h3><div class="page-list">${show.map(v=>`<button data-visit="${v.id}"><b>${v.date} · ${esc(v.meal)}</b><br>${esc(v.note)}</button>`).join('')||'<p class="hint">No visits yet.</p>'}</div>${vv.length>3?`<button data-action="more-visits" data-rid="${id}">Show more visits</button>`:''}<button class="text-button danger" data-delete="${id}">Delete restaurant</button></div>`,{full:true,cls:'entry-panel'});
}

function restaurantForm(id,defaults={}){
  const r={...(rest(id)||{name:'',kind:'shop',tags:[],address:'',note:'',wish:tab==='wishlist'}),...defaults};
  const located=Number.isFinite(r.lat)&&Number.isFinite(r.lng);
  openPanel(id?'Your Restaurant':r.wish?'Save for later':'Add a Restaurant',`
    <form id="restaurant-form" class="place-editor" data-edit-id="${id||''}">
      <div class="place-editor-scroll form-scroll">
        <section class="chosen-place"><div class="chosen-art">${art(r.kind)}</div><div><span class="eyebrow">${located?'A GOOD FIND':'YOUR NEXT FOOD ADVENTURE'}</span><h3>${esc(r.name||'A new favorite')}</h3><p>${esc(r.address||'Find a place, then make it yours.')}</p></div></section>
        <button type="button" class="change-place" data-action="search-current">${icon('search')} ${located?'Find a different place':'Find a restaurant on the map'} <span>›</span></button>
        ${located?'<div id="place-preview-map" class="place-preview-map" aria-label="Restaurant location preview"></div><div id="place-preview-status" class="preview-map-status" role="status" hidden></div>':''}
        <label for="r-name">Restaurant name</label><input id="r-name" name="name" required maxlength="100" placeholder="Name of your new favorite" value="${esc(r.name)}">
        <label for="r-address">Address</label><input id="r-address" name="address" maxlength="250" placeholder="Street, neighborhood, city" value="${esc(r.address)}">
        <div class="form-grid"><div><label for="r-kind">Food illustration</label><select id="r-kind" name="kind">${Object.keys(artIndex).filter(k=>k!=='cat').map(k=>`<option value="${k}" ${r.kind===k?'selected':''}>${k==='shop'?'Restaurant':k[0].toUpperCase()+k.slice(1)}</option>`).join('')}</select></div><div><label for="r-rating">Your rating <small>(optional)</small></label><input id="r-rating" name="rating" type="number" min="1" max="5" step="0.1" placeholder="★ 1–5" value="${r.rating||''}"></div></div>
        <label class="checkbox wish-toggle"><input type="checkbox" name="wish" ${r.wish?'checked':''}><span><b>♡ Keep on my wishlist</b></span></label>
        <button type="button" class="secondary" id="toggle-more-fields">More fields ▾</button>
        <div class="collapsed-more">
        <label for="r-tags">Categories</label><input id="r-tags" name="tags" maxlength="150" placeholder="e.g. Japanese, Ramen" value="${esc((r.tags||[]).join(', '))}">
        <label for="r-note">A little note</label><textarea id="r-note" name="note" maxlength="2000" placeholder="What caught your eye?">${esc(r.note)}</textarea>
        <details class="pin-settings"><summary>Adjust map location</summary><div class="form-grid"><div><label for="r-lat">Latitude</label><input id="r-lat" name="lat" type="number" min="-90" max="90" step="any" value="${r.lat??''}"></div><div><label for="r-lng">Longitude</label><input id="r-lng" name="lng" type="number" min="-180" max="180" step="any" value="${r.lng??''}"></div></div></details>
        </div>
        <input type="hidden" name="lat" value="${r.lat??''}" id="r-lat-hidden">
        <input type="hidden" name="lng" value="${r.lng??''}" id="r-lng-hidden">
      </div>
      <div class="form-actions place-save-bar"><button type="button" data-action="close-panel">Cancel</button><button class="primary">♡ ${id?'Save Changes':'Save Restaurant'}</button></div>
    </form>`,{full:true,cls:'place-panel entry-panel'});
  $('#toggle-more-fields')?.addEventListener('click',()=>{$('#restaurant-form').classList.toggle('show-more-fields');$('#toggle-more-fields').textContent=$('#restaurant-form').classList.contains('show-more-fields')?'Less fields ▴':'More fields ▾'});
  if(located&&typeof window.L!=='undefined'){
    placePreviewMap=window.L.map('place-preview-map',{zoomControl:false,dragging:false,scrollWheelZoom:false,doubleClickZoom:false,boxZoom:false,touchZoom:false,keyboard:false}).setView([r.lat,r.lng],15);
    createMapTiles(placePreviewMap,'#place-preview-status');
    window.L.circleMarker([r.lat,r.lng],{radius:9,color:'#38271f',weight:3,fillColor:'#fa746b',fillOpacity:1}).addTo(placePreviewMap);
  }
  $('#restaurant-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target);let lat=f.get('lat'),lng=f.get('lng');if(lat==null||lat==='')lat=(r.lat==null||r.lat===undefined)?'':String(r.lat);if(lng==null||lng==='')lng=(r.lng==null||r.lng===undefined)?'':String(r.lng);if((lat==='')!==(lng===''))return toast('Enter both latitude and longitude, or leave both empty.');const now=Date.now();const item={...r,id:id||uid(),name:f.get('name').trim(),address:f.get('address').trim(),kind:f.get('kind'),rating:f.get('rating')?Number(f.get('rating')):null,lat:lat===''?null:Number(lat),lng:lng===''?null:Number(lng),tags:String(f.get('tags')||r.tags&&r.tags.join(', ')||'').split(',').map(t=>t.trim()).filter(Boolean),note:f.get('note')!=null?String(f.get('note')).trim():(r.note||''),wish:f.has('wish'),added:r.added||today(),demo:false,u:now};if(!item.name)return toast('Please enter a restaurant name.');if(!commit(()=>{if(id)state.restaurants=state.restaurants.map(x=>x.id===id?item:x);else state.restaurants.push(item)}))return;selected=item.id;if(Number.isFinite(item.lat)){mapCenter=[item.lat,item.lng];mapZoom=16;if(map)map.setView(mapCenter,mapZoom)}closePanel();render();if(pendingVisit){pendingVisit=false;visitForm(item.id)}else toast('Restaurant saved!')};
}

function visitForm(restaurantId,visitId){
  if(!state.restaurants.length){pendingVisit=true;return showSearch({afterVisit:true})}
  const v=state.visits.find(v=>v.id===visitId)||{restaurantId:restaurantId||selected||state.restaurants[0].id,date:today(),time:new Date().toTimeString().slice(0,5),meal:'Lunch',rating:null,note:'',photos:[]};
  openPanel(visitId?'Edit Visit':'Add a Visit',`<form id="visit-form"><div class="form-scroll"><label for="v-restaurant">Restaurant</label><select id="v-restaurant" name="restaurantId">${state.restaurants.map(r=>`<option value="${r.id}" ${r.id===v.restaurantId?'selected':''}>${esc(r.name)}</option>`).join('')}</select><div class="form-grid"><div><label for="v-date">Date</label><input id="v-date" name="date" type="date" required value="${v.date}"></div><div><label for="v-time">Time</label><input id="v-time" name="time" type="time" required value="${v.time}"></div><div><label for="v-meal">Meal</label><select id="v-meal" name="meal">${['Breakfast','Brunch','Lunch','Dinner','Cafe','Dessert','Snack'].map(m=>`<option ${v.meal===m?'selected':''}>${m}</option>`).join('')}</select></div><div><label for="v-rating">Rating</label><input id="v-rating" name="rating" type="number" min="1" max="5" step="0.1" required placeholder="1–5" value="${v.rating??''}"></div></div><label for="v-note">What did you try?</label><textarea id="v-note" name="note" maxlength="2000" placeholder="A cozy broth…">${esc(v.note)}</textarea><label for="v-photo">Photos (up to 3)</label><input id="v-photo" type="file" accept="image/jpeg,image/png,image/webp" multiple><div class="photos">${(v.photos||[]).map(p=>`<img src="${p}" alt="Visit photo">`).join('')}</div>${v.photos?.length?'<label class="checkbox"><input type="checkbox" name="removePhotos"> Remove existing photos</label>':''}</div><div class="form-actions place-save-bar"><button type="button" data-action="close-panel">Cancel</button><button class="primary">Save Visit</button></div></form>`,{full:true,cls:'entry-panel'});
  $('#visit-form').onsubmit=async e=>{e.preventDefault();const form=e.target,f=new FormData(form),btn=form.querySelector('.primary');btn.disabled=true;try{let photos=f.has('removePhotos')?[]:[...(v.photos||[])];const files=[...($('#v-photo')?.files||[])];if(files.length+photos.length>3)throw Error('Keep up to 3 photos per visit.');for(const file of files)photos.push(await compressImage(file));if(!form.isConnected)return;const item={id:visitId||uid(),restaurantId:f.get('restaurantId'),date:f.get('date'),time:f.get('time'),meal:f.get('meal'),rating:Number(f.get('rating')),note:f.get('note').trim(),photos,u:Date.now()};if(!commit(()=>{if(visitId)state.visits=state.visits.map(x=>x.id===visitId?item:x);else state.visits.push(item)}))return;closePanel();render();toast('A delicious memory saved!')}catch(err){toast(err.message)}finally{btn.disabled=false}};
}
async function compressImage(file){if(!/^image\/(jpeg|png|webp)$/.test(file.type)||file.size>15000000)throw Error('Choose a JPG, PNG, or WebP under 15 MB.');const bmp=await createImageBitmap(file),scale=Math.min(1,1000/Math.max(bmp.width,bmp.height));const c=document.createElement('canvas');c.width=bmp.width*scale;c.height=bmp.height*scale;c.getContext('2d').drawImage(bmp,0,0,c.width,c.height);bmp.close();return c.toDataURL('image/jpeg',.72)}
function visitExpandHtml(v){
  const photos=(v.photos||[]).map(p=>`<img src="${p}" alt="Food from this visit">`).join('');
  return `<div class="visit-expand"><div class="visit-expand-meta"><span class="rating"><span class="star">★</span> ${v.rating}</span><span>${esc(v.time)} · ${esc(v.meal)}</span></div>${v.note?`<p class="visit-expand-note">${esc(v.note)}</p>`:''}${photos?`<div class="photos visit-expand-photos">${photos}</div>`:''}<div class="visit-expand-actions"><button type="button" data-editvisit="${v.id}">Edit</button><button type="button" class="danger" data-deletevisit="${v.id}">Delete</button></div></div>`;
}
function toggleTimelineVisit(id){
  expandedVisitId=expandedVisitId===id?null:id;
  // re-render list in place when possible
  if(tab==='timeline')renderTimeline();
}
function visitDetail(id){const v=state.visits.find(v=>v.id===id);if(!v)return;openPanel(rest(v.restaurantId)?.name||'Visit',`<div class="form-scroll"><p>${v.date} · ${esc(v.time)} · ${esc(v.meal)}</p><p class="rating"><span class="star">★</span> ${v.rating}</p><p>${esc(v.note)}</p><div class="photos">${(v.photos||[]).map(p=>`<img src="${p}" alt="Food from this visit">`).join('')}</div><div class="form-actions"><button data-editvisit="${id}">Edit Visit</button><button class="danger" data-deletevisit="${id}">Delete Visit</button></div></div>`,{full:true,cls:'entry-panel'})}

let activeSearch=null, searchGeneration=0, autocompleteTimer=null, lastSearchAt=0, placePreviewMap=null, searchResultPage=0;
function destroyPlacePreview(){if(placePreviewMap){placePreviewMap.remove();placePreviewMap=null}}
function cancelSearch(){clearTimeout(autocompleteTimer);searchGeneration++;activeSearch?.abort();activeSearch=null;searchBusy=false}
function validPlace(f){
  const c=f?.geometry?.coordinates;return f?.geometry?.type==='Point'&&f.properties&&Array.isArray(c)&&Number.isFinite(c[0])&&Math.abs(c[0])<=180&&Number.isFinite(c[1])&&Math.abs(c[1])<=90
}
function placeSearchURL(query,center,nearMap=true){
  const params=new URLSearchParams({q:query,limit:'8',lat:String(center[0]),lon:String(center[1]),zoom:'13',location_bias_scale:'0.2'});
  for(const type of ['amenity:restaurant','amenity:cafe','amenity:fast_food','amenity:food_court','amenity:bar','amenity:pub','amenity:ice_cream','shop:bakery'])params.append('osm_tag',type);
  if(nearMap)params.set('bbox',[Math.max(-180,center[1]-.45),Math.max(-90,center[0]-.27),Math.min(180,center[1]+.45),Math.min(90,center[0]+.27)].join(','));
  return 'https://photon.komoot.io/api/?'+params.toString();
}
function mapboxForwardURL(query,center,nearMap){
  const params=new URLSearchParams({q:query,access_token:MAPBOX_TOKEN,language:'en',limit:'8',types:'poi'});
  if(nearMap&&Array.isArray(center)&&center.length>=2){
    params.set('proximity',`${center[1]},${center[0]}`);
    params.set('bbox',[Math.max(-180,center[1]-.45),Math.max(-90,center[0]-.27),Math.min(180,center[1]+.45),Math.min(90,center[0]+.27)].join(','));
  }
  return 'https://api.mapbox.com/search/searchbox/v1/forward?'+params.toString();
}
function mapboxForwardFeatures(features){
  return (features||[]).filter(f=>validPlace(f)).map(f=>{
    const p=f.properties||{},ctx=p.context||{};
    return {type:'Feature',geometry:f.geometry,properties:{
      _provider:'mapbox',mapbox_id:p.mapbox_id||null,
      name:p.name_preferred||p.name,full_address:p.full_address||'',address:p.address||'',place_formatted:p.place_formatted||'',
      housenumber:ctx.address?.address_number,street:ctx.address?.street_name||ctx.street?.name,
      district:ctx.neighborhood?.name,city:ctx.place?.name,state:ctx.region?.name,country:ctx.country?.name,
      poi_category:p.poi_category||[],osm_value:(p.poi_category_ids||[])[0]||'',
      sourceId:p.mapbox_id?`mapbox:${p.mapbox_id}`:null
    }};
  });
}
function manualFallback(){return `<details class="manual-fallback"><summary>Can’t find it?</summary><p>Enter details manually.</p><button type="button" class="manual-last-resort" data-action="manual">Enter manually</button></details>`}
function hitDistanceLabel(f){
  if(!userLocation)return '';
  const c=f?.geometry?.coordinates;
  if(!Array.isArray(c)||!Number.isFinite(c[0])||!Number.isFinite(c[1]))return '';
  const rad=x=>x*Math.PI/180,dlat=rad(c[1]-userLocation[0]),dlng=rad(c[0]-userLocation[1]);
  const a=Math.sin(dlat/2)**2+Math.cos(rad(c[1]))*Math.cos(rad(userLocation[0]))*Math.sin(dlng/2)**2;
  const km=6371*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
  return km<1?Math.round(km*1000)+' m':km.toFixed(1)+' km';
}

function sheetCoverPx(){
  const s=$('#sheet')?.querySelector('.search-sheet,.detail-sheet');
  return s?Math.round(s.getBoundingClientRect().height):0;
}
function centerMapAboveSheet(lat,lng,zoom){
  if(!map||!Number.isFinite(lat)||!Number.isFinite(lng))return;
  const z=zoom!=null?zoom:Math.max(map.getZoom(),16);
  const mc=map.getContainer().getBoundingClientRect();
  let top=mc.top,bottom=mc.bottom;
  const sb=document.querySelector('.map-search-bar');
  if(sb){const r=sb.getBoundingClientRect();if(r.height&&r.bottom>top&&r.bottom<bottom)top=r.bottom}
  const hv=document.querySelector('.map-hide-visited:not([hidden])');
  if(hv){const r=hv.getBoundingClientRect();if(r.height&&r.bottom>top&&r.bottom<bottom)top=r.bottom}
  const s=$('#sheet')?.querySelector('.search-sheet,.detail-sheet');
  if(s){const r=s.getBoundingClientRect();if(r.height&&r.top<bottom&&r.top>top)bottom=r.top}
  // visible-area midpoint relative to raw container centre (in px)
  const dy=((top+bottom)/2-mc.top)-mc.height/2;
  const target=map.unproject(map.project([lat,lng],z).subtract([0,dy]),z);
  map.setView(target,z,{animate:true});
}
function pinVisibleAboveSheet(lat,lng){
  const pt=map.latLngToContainerPoint([lat,lng]),sz=map.getSize(),cover=sheetCoverPx()||0;
  return pt.x>20&&pt.x<sz.x-20&&pt.y>90&&pt.y<sz.y-cover-10;
}
function dismissSearchSheet(){
  // keep searchResults + blue pins; only Clear / new search / leaving map tab removes them
  const sheet=$('#sheet');if(sheet)renderSheet();
  syncHideVisitedChip();
}
function bindSheetDismiss(root,onDismiss){
  if(!root||root.dataset.dismissBound)return;
  root.dataset.dismissBound='1';
  const grips=[root.querySelector('.handle'),root.querySelector('.search-sheet-head,.sheet-head')].filter(Boolean);
  if(!grips.length)return;
  let startY=0,dy=0,dragging=false,pid=null;
  const threshold=()=>Math.max(64,Math.round(root.getBoundingClientRect().height*0.28));
  const onMove=e=>{
    if(!dragging||e.pointerId!==pid)return;
    dy=e.clientY-startY;
    if(dy<0)dy=0;
    root.style.transform=`translateY(${dy}px)`;
    root.style.opacity=String(Math.max(0.35,1-dy/Math.max(180,root.offsetHeight)));
  };
  const onUp=e=>{
    if(!dragging||e.pointerId!==pid)return;
    dragging=false;pid=null;
    root.classList.remove('sheet-dragging');
    try{root.releasePointerCapture(e.pointerId)}catch{}
    window.removeEventListener('pointermove',onMove);
    window.removeEventListener('pointerup',onUp);
    window.removeEventListener('pointercancel',onUp);
    if(dy>=threshold()){
      root.style.transform=`translateY(${root.offsetHeight+40}px)`;
      root.style.opacity='0';
      setTimeout(()=>{root.style.transform='';root.style.opacity='';onDismiss&&onDismiss()},180);
    }else{
      root.style.transform='';root.style.opacity='';
    }
    dy=0;
  };
  const onDown=e=>{
    if(e.button!=null&&e.button!==0)return;
    // ignore interactive controls inside header (Clear, wishlist toggle, etc.)
    if(e.target.closest('button,a,input,select,textarea,label'))return;
    dragging=true;pid=e.pointerId;startY=e.clientY;dy=0;
    root.classList.add('sheet-dragging');
    try{root.setPointerCapture(e.pointerId)}catch{}
    window.addEventListener('pointermove',onMove,{passive:false});
    window.addEventListener('pointerup',onUp);
    window.addEventListener('pointercancel',onUp);
  };
  grips.forEach(g=>{
    g.addEventListener('pointerdown',onDown);
  });
}
function openSearchHitFromPin(i){
  const sheet=$('#sheet');if(!sheet||!searchResults[i])return;
  if(selected){selected=null;updateMarkerIcons()}
  if(!sheet.querySelector('.search-sheet .place-hits')){
    const keep=searchResults.slice();
    showSearchSheetResults(sheet,keep,{keepMarkers:true});
  }
  focusSearchHit(i,{fromPin:true});
}
function focusSearchHit(i,opts={}){
  const f=searchResults[Number(i)];if(!f||!map)return;
  const c=f.geometry?.coordinates;if(!c)return;
  if(opts.fromPin){
    requestAnimationFrame(()=>{if(!pinVisibleAboveSheet(c[1],c[0]))centerMapAboveSheet(c[1],c[0],map.getZoom())});
  }else centerMapAboveSheet(c[1],c[0],Math.max(map.getZoom(),16));
  $$('.place-hit').forEach(x=>x.classList.remove('hit-focus'));
  const el=document.querySelector(`.place-hit[data-hit="${i}"]`);
  el?.classList.add('hit-focus');
  el?.scrollIntoView({block:'nearest',behavior:'smooth'});
  searchFocusIdx=Number(i);
  searchMarkers.forEach((mk,j)=>{if(mk&&searchResults[j])mk.setIcon(searchResultIcon(searchResults[j],j))});
}
function placeHitHtml(f,i){
  const p=f.properties,dist=hitDistanceLabel(f),addr=placeAddress(p);
  const meta=`${dist?`<span class="hit-dist">${esc(dist)}</span>${addr?' · ':''}`:''}${esc(addr)}`;
  return `<article class="place-hit" data-hit="${i}" data-hit-focus="${i}" role="button" tabindex="0"><div class="place-hit-info"><div class="place-hit-title"><b>${esc(p.name||p.street||'Place')}</b><div class="place-hit-actions"><button type="button" class="hit-icon" data-result-wish="${i}" aria-label="Save to wishlist" title="Wishlist"><img src="assets/icon-wish-meow.png?v=ui20261015ar" alt="" width="26" height="26" decoding="async"></button><button type="button" class="hit-icon" data-result-add="${i}" aria-label="Add restaurant" title="Add"><img src="assets/icon-add-meow.png?v=ui20261015ar" alt="" width="26" height="26" decoding="async"></button></div></div><small>${meta}</small></div></article>`;
}
function renderPlaceHits(output,features,opts={}){
  searchResults=(features||[]).filter(validPlace);
  if(!output)return;
  const visible=searchResults.map((f,i)=>searchHitHidden(f)?null:i).filter(i=>i!=null);
  const head=document.querySelector('.search-sheet-head h2');
  if(head)head.textContent=visible.length?`Nearby matches · ${visible.length}`:'Nearby matches';
  syncHideVisitedChip();
  const cb=document.querySelector('[data-hide-visited]');
  if(cb)cb.checked=hideVisited;
  if(searchFocusIdx!=null&&(searchHitHidden(searchResults[searchFocusIdx])||!searchResults[searchFocusIdx]))searchFocusIdx=null;
  if(!searchResults.length){clearSearchMarkers();output.classList.remove('can-scroll');output.innerHTML='<div class="search-idle"><p>No nearby matches. Try another name.</p></div>'+manualFallback();return}
  if(!visible.length){
    clearSearchMarkers();output.classList.remove('can-scroll');
    output.innerHTML=`<div class="search-idle"><p>${hideVisited?'No unvisited matches nearby. Turn off Hide visited to see places you’ve been.':'No nearby matches. Try another name.'}</p></div>`+manualFallback();
    return;
  }
  output.innerHTML=`<div class="place-hits">${visible.map(i=>placeHitHtml(searchResults[i],i)).join('')}</div>`+manualFallback();
  const hits=output.querySelector('.place-hits');
  requestAnimationFrame(()=>{
    if(!hits||!output.isConnected)return;
    const row=hits.querySelector('.place-hit');
    if(row){
      const rh=row.getBoundingClientRect().height||48;
      hits.style.setProperty('--place-hit-h',rh+'px');
      hits.style.maxHeight=Math.round(rh*3.5)+'px';
    }
    output.classList.toggle('can-scroll',hits.scrollHeight>hits.clientHeight+4);
  });
  if(!(opts.keepMarkers&&searchMarkers.length===searchResults.length))drawSearchMarkers();
}
function searchCenter(){return searchContext.center||userLocation||mapCenter}
function demoPlaceFeatures(){
  const [lat0,lng0]=DEFAULT_CENTER;
  const places=[
    {name:'Demo Noodle House',addr:'88 West Cordova St, Vancouver, BC',dlat:0.0018,dlng:-0.0024,cat:['restaurant'],val:'restaurant'},
    {name:'Harbour Cat Cafe',addr:'375 Water St, Vancouver, BC',dlat:0.0032,dlng:-0.0008,cat:['cafe','coffee'],val:'cafe'},
    {name:'Gastown Dumpling Co.',addr:'12 Powell St, Vancouver, BC',dlat:0.0024,dlng:0.0016,cat:['restaurant'],val:'restaurant'},
    {name:'Meowsto Ramen Lab',addr:'450 Granville St, Vancouver, BC',dlat:-0.0012,dlng:-0.0015,cat:['restaurant'],val:'ramen'},
    {name:'False Creek Sushi Bar',addr:'1011 Beach Ave, Vancouver, BC',dlat:-0.0045,dlng:-0.0032,cat:['restaurant'],val:'sushi'},
    {name:'Stanley Park Bakehouse',addr:'2099 Beach Ave, Vancouver, BC',dlat:0.0060,dlng:-0.0080,cat:['bakery','cafe'],val:'bakery'},
    {name:'Yaletown Burger Club',addr:'1144 Homer St, Vancouver, BC',dlat:-0.0038,dlng:0.0006,cat:['restaurant'],val:'fast_food'},
    {name:'Kitsilano Soft Serve',addr:'2200 West 4th Ave, Vancouver, BC',dlat:-0.0085,dlng:-0.0140,cat:['ice_cream'],val:'ice_cream'}
  ];
  return places.map((p,i)=>({
    type:'Feature',
    geometry:{type:'Point',coordinates:[lng0+p.dlng,lat0+p.dlat]},
    properties:{
      _provider:'demo',sourceId:'demo:'+(i+1),
      name:p.name,full_address:p.addr,address:p.addr,place_formatted:'Vancouver, British Columbia',
      city:'Vancouver',state:'British Columbia',country:'Canada',
      poi_category:p.cat,osm_value:p.val
    }
  }));
}
async function fetchPlaceFeatures(q,signal){
  if(String(q||'').trim().toLowerCase()==='demo')return demoPlaceFeatures();
  const center=searchCenter();
  const key=searchCacheKey(q,center),hit=searchCacheGet(key);if(hit)return hit;
  const out=await fetchPlaceFeaturesLive(q,center,signal);
  if(out&&out.length)searchCachePut(key,out);
  return out;
}
const SEARCH_CACHE_KEY='meowsto-search-cache-v1',SEARCH_CACHE_TTL=7*864e5,SEARCH_CACHE_MAX=60;
function searchCacheKey(q,c){const n=String(q||'').trim().toLowerCase().replace(/\s+/g,' ');const p=Array.isArray(c)&&c.length>=2?`${(+c[0]).toFixed(2)},${(+c[1]).toFixed(2)}`:'none';return n+'@'+p}
function searchCacheLoad(){try{return JSON.parse(localStorage.getItem(SEARCH_CACHE_KEY)||'{}')||{}}catch{return {}}}
function searchCacheGet(k){const c=searchCacheLoad(),e=c[k];if(!e)return null;if(Date.now()-e.t>SEARCH_CACHE_TTL){delete c[k];try{localStorage.setItem(SEARCH_CACHE_KEY,JSON.stringify(c))}catch{}return null}return e.f}
function searchCachePut(k,f){const c=searchCacheLoad();c[k]={t:Date.now(),f};const ks=Object.keys(c).sort((a,b)=>c[a].t-c[b].t);while(ks.length>SEARCH_CACHE_MAX)delete c[ks.shift()];try{localStorage.setItem(SEARCH_CACHE_KEY,JSON.stringify(c))}catch{}}
async function fetchPlaceFeaturesLive(q,center,signal){
  try{
    const res=await fetch(mapboxForwardURL(q,center,true),{signal});
    if(!res.ok)throw Error('mapbox '+res.status);
    const json=await res.json();
    if(!Array.isArray(json.features))throw Error('mapbox invalid');
    return mapboxForwardFeatures(json.features);
  }catch(mbErr){
    if(mbErr?.name==='AbortError')throw mbErr;
    const res=await fetch(placeSearchURL(q,center,true),{signal});
    if(!res.ok)throw Error('Search unavailable');
    const data=await res.json();
    if(!Array.isArray(data.features))throw Error('Invalid');
    return data.features.filter(validPlace);
  }
}
function showSearchSheetResults(sheet,features,opts={}){
  sheet.innerHTML=`<section class="search-sheet"><div class="handle" aria-hidden="true"></div><div class="search-sheet-head"><h2>Nearby matches</h2><div class="search-sheet-tools"><button type="button" class="text-button" data-action="clear-search-sheet">Clear</button></div></div><div id="search-results" class="search-results place-results"></div></section>`;
  renderPlaceHits($('#search-results'),features,opts);
  bindSheetDismiss(sheet.querySelector('.search-sheet'),dismissSearchSheet);
  syncHideVisitedChip();
}
function wireMapSearch(){
  const form=$('#map-search-form'),input=$('#map-search-query');
  if(!form||!input||form.dataset.wired)return;
  form.dataset.wired='1';
  form.onsubmit=async e=>{
    e.preventDefault();clearTimeout(autocompleteTimer);
    const q=input.value.trim();if(q.length<2)return toast('Enter at least two characters.');
    selected=null;lastSearchQuery=q;
    const sheet=$('#sheet');if(!sheet)return;
    // Same query + map-center key as last successful search → re-show cached sheet only (no Mapbox)
    const center=searchCenter();
    const cacheKey=searchCacheKey(q,center);
    const cached=String(q||'').trim().toLowerCase()==='demo'?null:searchCacheGet(cacheKey);
    if(cached){
      showSearchSheetResults(sheet,cached);
      return;
    }
    sheet.innerHTML=`<section class="search-sheet"><div class="handle" aria-hidden="true"></div><p class="search-message loading" role="status">Searching nearby…</p></section>`;
    bindSheetDismiss(sheet.querySelector('.search-sheet'),dismissSearchSheet);
    syncHideVisitedChip();
    if(searchBusy){activeSearch?.abort();searchGeneration++;searchBusy=false}
    const generation=++searchGeneration,controller=new AbortController();activeSearch=controller;searchBusy=true;
    const timeout=setTimeout(()=>controller.abort(),9000);
    try{
      const features=await fetchPlaceFeatures(q,controller.signal);
      if(generation!==searchGeneration||!sheet.isConnected)return;
      showSearchSheetResults(sheet,features);
    }catch{
      if(generation!==searchGeneration||!sheet.isConnected)return;
      sheet.innerHTML=`<section class="search-sheet"><div class="handle" aria-hidden="true"></div><div class="search-idle" role="status"><h3>Connection hiccup</h3><p>Try again in a moment.</p><button type="button" id="retry-place-search">Try again</button></div>${manualFallback()}</section>`;
      bindSheetDismiss(sheet.querySelector('.search-sheet'),dismissSearchSheet);
      $('#retry-place-search')?.addEventListener('click',()=>form.requestSubmit());
    }finally{
      clearTimeout(timeout);
      if(generation===searchGeneration){activeSearch=null;searchBusy=false}
    }
  };
}
function showSearch(context={}){
  cancelSearch();searchContext=context;searchResultPage=0;
  // Prefer map search bar; keep a slim panel only when editing a place mid-form
  if(context.editId){
    openPanel('Find a place',`
      <form class="search-form place-search-form compact" id="search-form"><div class="place-search-input"><input id="search-query" placeholder="Restaurant nearby" aria-label="Search restaurants" autocomplete="off" required minlength="2" maxlength="200"></div><button class="search-submit" aria-label="Search">→</button></form>
      <div id="search-results" class="search-results place-results"><div class="search-idle"><p>Type a name, then tap search. Nearby matches will list here.</p></div></div>
      <footer class="place-search-footer"><small>Mapbox · Photon fallback</small></footer>`,{cls:'search-panel compact-search'});
    const form=$('#search-form'),input=$('#search-query'),output=$('#search-results');
    form.onsubmit=async e=>{
      e.preventDefault();const q=input.value.trim();if(q.length<2)return toast('Enter at least two characters.');
      lastSearchQuery=q;
      if(searchBusy){activeSearch?.abort();searchGeneration++;searchBusy=false}
      const generation=++searchGeneration,controller=new AbortController();activeSearch=controller;searchBusy=true;
      output.innerHTML='<p class="search-message loading" role="status">Searching nearby…</p>';
      const timeout=setTimeout(()=>controller.abort(),9000);
      try{
        const features=await fetchPlaceFeatures(q,controller.signal);
        if(generation!==searchGeneration||!output.isConnected)return;
        renderPlaceHits(output,features);
      }catch{
        if(generation!==searchGeneration||!output.isConnected)return;
        output.innerHTML='<div class="search-idle" role="status"><p>Couldn’t search. Try again.</p><button type="button" id="retry-place-search">Try again</button></div>'+manualFallback();
        $('#retry-place-search')?.addEventListener('click',()=>form.requestSubmit());
      }finally{clearTimeout(timeout);if(generation===searchGeneration){activeSearch=null;searchBusy=false}}
    };
    setTimeout(()=>input?.focus(),50);
    return;
  }
  closePanel();
  if(tab!=='map'){tab='map';render()}
  else if(!$('#map-search-form'))render();
  else wireMapSearch();
  setTimeout(()=>{const input=$('#map-search-query');if(input){input.focus();if(context.wish)toast('Search, then tap Wishlist on a result')}},60);
}
function openFromSearchFeature(f,mode){
  clearSearchMarkers();searchResults=[];searchFocusIdx=null;syncHideVisitedChip();
  const p=f.properties,coords=f.geometry.coordinates;
  const sourceId=p.sourceId||(p.osm_type&&p.osm_id?`${p.osm_type}:${p.osm_id}`:null)||(p.mapbox_id?`mapbox:${p.mapbox_id}`:null);
  const wantWish=mode==='wish'||(mode!=='add'&&(searchContext.wish||tab==='wishlist'));
  const existing=state.restaurants.find(r=>sourceId&&r.sourceId===sourceId||r.name===(p.name||p.street)&&r.lat===coords[1]&&r.lng===coords[0]);
  if(existing&&existing.id!==searchContext.editId){
    if(wantWish&&!existing.wish&&!commit(()=>{rest(existing.id).wish=true;rest(existing.id).u=Date.now()}))return;
    if(pendingVisit){pendingVisit=false;return visitForm(existing.id)}
    if(wantWish){toast(existing.wish?'Already on wishlist':'Saved to wishlist');closePanel();render();return}
    return restaurantDetail(existing.id);
  }
  return restaurantForm(searchContext.editId||null,{...searchContext.draft,name:p.name||p.street||'New restaurant',address:placeAddress(p),lat:coords[1],lng:coords[0],wish:wantWish,sourceId,...placeCategory(p)});
}

function placeCategory(p){
  const cats=(p.poi_category||[]).join(' ').toLowerCase();
  const type=String(p.osm_value||'').toLowerCase(),name=String(p.name||'').toLowerCase();
  const blob=type+' '+name+' '+cats;
  if(/cafe|coffee/.test(blob))return {kind:'cafe',tags:['Cafe']};
  if(/ramen/.test(blob))return {kind:'ramen',tags:['Ramen','Japanese']};
  if(/sushi/.test(blob))return {kind:'sushi',tags:['Sushi','Japanese']};
  if(/burger/.test(blob))return {kind:'burger',tags:['Burgers']};
  if(/ice_cream|bakery|cake|dessert|sweet/.test(blob))return {kind:'dessert',tags:['Dessert']};
  if(/pizza|pasta|italian/.test(blob))return {kind:'pasta',tags:['Italian']};
  return {kind:'shop',tags:[]};
}
function placeAddress(p){
  if(p.full_address)return p.full_address;
  if(p._provider==='mapbox')return [p.address,p.place_formatted].filter(Boolean).join(', ')||[p.housenumber,p.street,p.city,p.country].filter(Boolean).join(', ');
  return [...new Set([p.housenumber,p.street,p.district,p.city,p.state,p.country].filter(Boolean))].join(', ')
}
function openFromSearchFeature(f){
  const p=f.properties,coords=f.geometry.coordinates;
  const sourceId=p.sourceId||(p.osm_type&&p.osm_id?`${p.osm_type}:${p.osm_id}`:null)||(p.mapbox_id?`mapbox:${p.mapbox_id}`:null);
  const existing=state.restaurants.find(r=>sourceId&&r.sourceId===sourceId||r.name===(p.name||p.street)&&r.lat===coords[1]&&r.lng===coords[0]);
  if(existing&&existing.id!==searchContext.editId){if(searchContext.wish&&!existing.wish&&!commit(()=>{rest(existing.id).wish=true;rest(existing.id).u=Date.now()}))return;if(pendingVisit){pendingVisit=false;return visitForm(existing.id)}return restaurantDetail(existing.id)}
  return restaurantForm(searchContext.editId||null,{...searchContext.draft,name:p.name||p.street||'New restaurant',address:placeAddress(p),lat:coords[1],lng:coords[0],wish:searchContext.wish??tab==='wishlist',sourceId,...placeCategory(p)})
}

function logo(){return '<img class="meowsto-logo" src="assets/meowsto-logo-256.png?v=ui20261015m" alt="">'}
function initialOf(){const n=String(USER||'?').trim();return (n.match(/[\p{L}\p{N}]/u)?.[0]||'?').toUpperCase()}
function avatarHtml(){const p=state.avatar;return (typeof p==='string'&&/^data:image\/(jpeg|png|webp);base64,/.test(p))?`<img src="${p}" alt="">`:`<span class="avatar-initial">${esc(initialOf())}</span>`}
function renderAvatar(){const b=document.querySelector('header .avatar');if(b)b.innerHTML=avatarHtml()}
async function avatarImage(file){if(!/^image\/(jpeg|png|webp)$/.test(file.type)||file.size>15000000)throw Error('Choose a JPG, PNG, or WebP under 15 MB.');const bmp=await createImageBitmap(file),s=Math.min(bmp.width,bmp.height),c=document.createElement('canvas');c.width=c.height=192;c.getContext('2d').drawImage(bmp,(bmp.width-s)/2,(bmp.height-s)/2,s,s,0,0,192,192);bmp.close();return c.toDataURL('image/jpeg',.8)}
function profile(){
  openPanel('Your profile',`<div class="profile-panel form-scroll"><div class="profile-avatar">${avatarHtml()}</div><div class="avatar-actions"><button data-action="avatar-upload">Change photo</button>${state.avatar?'<button data-action="avatar-letter">Use initial</button>':''}</div><input type="file" id="avatar-file" accept="image/jpeg,image/png,image/webp" hidden><h3 style="text-align:center">${esc(/[\u3400-\u9fff]/.test(state.profile||'')?'My food journal':(state.profile||'My food journal'))}</h3><p style="text-align:center;font-size:14px;color:#6d655c">@${esc(USER||'')}</p><div class="stats"><div><b>${state.restaurants.length}</b>Places</div><div><b>${state.visits.length}</b>Visits</div><div><b>${state.restaurants.filter(r=>r.wish).length}</b>To try</div></div><p class="hint">Your journal is encrypted on this device with AES-256-GCM before it’s uploaded, so the server can’t read it. If you forget your password, your data can’t be recovered.</p><div class="profile-actions"><button data-action="all-places">All my restaurants</button><button data-action="export">↓ Export backup</button><button data-action="import">↑ Import backup</button><button data-action="logout" class="danger">Log out</button></div><input type="file" id="import-file" accept="application/json,.json" hidden><p class="hint meowsto-sign">${logo()} Meowsto · Good food, good days.</p></div>`,{full:true,cls:'entry-panel'});
  $('#import-file').onchange=importBackup;
  $('#avatar-file').onchange=async e=>{const f=e.target.files[0];if(!f)return;try{const url=await avatarImage(f);if(commit(()=>{state.avatar=url})){renderAvatar();profile();toast('Profile photo updated')}}catch(err){toast(err.message||'Could not use that image')}};
}
function downloadJson(text,name){const url=URL.createObjectURL(new Blob([text],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
function exportBackup(){downloadJson(JSON.stringify(state,null,2),`meowsto-${today()}.json`);toast('Backup exported')}
async function importBackup(e){const file=e.target.files[0];if(!file)return;try{if(file.size>15000000)throw Error();let d=JSON.parse(await file.text());if(!validBackup(d))throw Error();d=removeLegacySamples(d);openPanel('Replace your journal?',`<p>This backup contains ${d.restaurants.length} restaurants and ${d.visits.length} visits. Importing replaces your cloud journal.</p><div class="form-actions"><button data-action="export">Export current</button><button class="primary" id="confirm-import">Replace journal</button></div>`,{full:true});$('#confirm-import').onclick=()=>{if(!commit(()=>{state=RL.migrate(d)}))return;selected=state.restaurants[0]?.id;closePanel();render();toast('Journal imported')}}catch{toast('Not a valid Meowsto backup.')}}
function confirmAction(title,message,fn){openPanel(title,`<p>${message}</p><div class="form-actions"><button data-action="close-panel">Cancel</button><button class="primary" id="confirm-action">Confirm</button></div>`,{full:true});$('#confirm-action').onclick=()=>{if(!commit(fn))return;closePanel();render();toast('Done')}}
function locate(){if(!navigator.geolocation)return toast('Location unavailable.');toast('Finding your location…');navigator.geolocation.getCurrentPosition(p=>{userLocation=[p.coords.latitude,p.coords.longitude];mapCenter=userLocation;mapZoom=15;if(map)map.setView(mapCenter,mapZoom);if(tab!=='map')tab='map';render();toast('Map centered')},()=>toast('Location unavailable or denied.'),{enableHighAccuracy:true,timeout:10000})}

document.addEventListener('change',e=>{
  const t=e.target;
  if(t&&t.matches&&t.matches('[data-hide-visited]')){
    hideVisited=!!t.checked;
    try{localStorage.setItem(HIDE_VISITED_KEY,hideVisited?'1':'0')}catch{}
    if(hideVisited&&selected&&visits(selected).length){selected=null;renderSheet();enhanceIcons()}
    drawMarkers();
    syncHideVisitedChip();
  }
});
document.addEventListener('click',e=>{
  const b=e.target.closest('button,[data-detail],[data-visit-toggle],[data-hit-focus]');if(!b)return;const d=b.dataset;
  if(d.page==='prev'){listPage=Math.max(0,listPage-1);if(tab==='wishlist'){renderWishlist();enhanceIcons()}return}
  if(d.page==='next'){listPage++;if(tab==='wishlist'){renderWishlist();enhanceIcons()}return}

  if(d.tab){if(d.tab!=='timeline')expandedVisitId=null;if(d.tab!=='map'){searchResults=[];searchFocusIdx=null;clearSearchMarkers()}tab=d.tab;closePanel();render();return}
  if(d.filter){filter=d.filter;listPage=0;render();return}
  if(d.detail)return restaurantDetail(d.detail);
  if(d.edit)return restaurantForm(d.edit);
  if(d.map){const r=rest(d.map);selected=r.id;mapCenter=[r.lat,r.lng];mapZoom=16;if(map)map.setView(mapCenter,mapZoom);tab='map';closePanel();render();return}
  if(d.addvisit)return visitForm(d.addvisit);
  if(d.visitToggle){toggleTimelineVisit(d.visitToggle);return}
  if(d.visit)return visitDetail(d.visit);
  if(d.editvisit)return visitForm(null,d.editvisit);
  if(d.deletevisit)return confirmAction('Delete this visit?','This visit and its photos will be removed.',()=>{state.del=state.del||{};state.del['v:'+d.deletevisit]=Date.now();state.visits=state.visits.filter(v=>v.id!==d.deletevisit);if(expandedVisitId===d.deletevisit)expandedVisitId=null});
  if(d.delete)return confirmAction('Delete restaurant?','This restaurant and all its visits will be removed.',()=>{state.del=state.del||{};state.del['r:'+d.delete]=Date.now();state.restaurants=state.restaurants.filter(r=>r.id!==d.delete);state.visits=state.visits.filter(v=>v.restaurantId!==d.delete)});
  if(d.explore!=null){const x=exploreResults[+d.explore];if(x){map?.closePopup();restaurantForm(null,{name:x.name,address:x.address,lat:x.lat,lng:x.lng,wish:true,kind:x.amenity==='cafe'?'cafe':'shop'})}return}
  if(d.save){if(!commit(()=>{const x=rest(d.save);x.wish=!x.wish;x.u=Date.now()}))return;if(!$('#panel').hidden)restaurantDetail(d.save);render();toast(rest(d.save).wish?'Saved to wishlist':'Removed from wishlist');return}
  if(d.note){const r=rest(d.note);openPanel('My note',`<form id="note-form"><textarea aria-label="My note" maxlength="2000">${esc(r.note)}</textarea><div class="form-actions"><button class="primary">Save note</button></div></form>`,{full:true});$('#note-form').onsubmit=e=>{e.preventDefault();if(!commit(()=>{rest(d.note).note=e.target.querySelector('textarea').value;rest(d.note).u=Date.now()}))return;closePanel();render();toast('Note saved')};return}
  if(d.hitFocus!==undefined){focusSearchHit(d.hitFocus);return}
  if(d.resultWish!==undefined){const f=searchResults[Number(d.resultWish)];if(!f)return;return openFromSearchFeature(f,'wish')}
  if(d.resultAdd!==undefined){const f=searchResults[Number(d.resultAdd)];if(!f)return;return openFromSearchFeature(f,'add')}
  if(d.result!==undefined){const f=searchResults[Number(d.result)];if(!f)return;return openFromSearchFeature(f)}
  switch(d.action){
    case'close':case'close-panel':pendingVisit=false;closePanel();break;
    case'clear-search-sheet':searchResults=[];searchFocusIdx=null;clearSearchMarkers();if($('#sheet'))renderSheet();syncHideVisitedChip();break;
    case'add':pendingVisit=false;showSearch();break;
    case'manual':restaurantForm(searchContext.editId||null,{...searchContext.draft,name:$('#search-query')?.value.trim()||'',wish:searchContext.wish??tab==='wishlist'});break;
    case'explore':exploreOn=!exploreOn;if(!exploreOn&&exploreLayer){exploreLayer.remove();exploreLayer=null}selected=null;render();toast(exploreOn?'Explore on: nearby places':'Explore off: your pins');break;
    case'add-wish':case'search-wish':pendingVisit=false;showSearch({wish:true});break;
    case'visit':visitForm();break;
    case'search-current':{const form=$('#restaurant-form'),f=new FormData(form);showSearch({wish:f.has('wish'),afterVisit:pendingVisit,editId:form.dataset.editId,draft:{note:f.get('note'),rating:f.get('rating')?Number(f.get('rating')):null}});break;}
    case'search':pendingVisit=false;showSearch();break;
    case'locate':locate();break;
    case'profile':profile();break;
    case'export':exportBackup();break;
    case'avatar-upload':$('#avatar-file')?.click();break;
    case'avatar-letter':if(commit(()=>{delete state.avatar}))profile(),renderAvatar();break;
    case'import':$('#import-file')?.click();break;
    case'logout':doLogout();break;
    case'all-places':{const rows=state.restaurants;const {slice,pages,total}=pageSlice(rows);openPanel('All my restaurants',`<div class="page-list">${slice.map(r=>`<button class="all-place" data-detail="${r.id}">${esc(r.name)} <span>›</span></button>`).join('')||'<p>No restaurants yet.</p>'}${pagerHtml(pages,total,'')}</div>`,{full:true});break;}
    case'more-visits':{const id=d.rid,vv=visits(id);openPanel('All visits',`<div class="page-list">${vv.map(v=>`<button data-visit="${v.id}"><b>${v.date} · ${esc(v.meal)}</b><br>${esc(v.note)}</button>`).join('')}</div>`,{full:true});break;}
    case'filters':openPanel('Sort your wishlist',`<label for="wish-sort">Order</label><select id="wish-sort"><option value="newest">Recently added</option><option value="rating">Highest rated</option><option value="name">Name A–Z</option></select>`,{full:true});$('#wish-sort').value=sort;$('#wish-sort').onchange=e=>{sort=e.target.value;closePanel();render()};break;
    case'more-filters':{$('.filters')?.classList.toggle('expanded');break;}
    case'retry-map':if(baseLayer){$('#map-status').hidden=true;baseLayer.redraw()}break;
    case'reload-map':location.reload();break;
  }
});
document.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target.matches('[role=button]')){e.preventDefault();e.target.click()}if(e.key==='Escape'&&!$('#panel').hidden)closePanel()});
document.addEventListener('change',e=>{if(e.target.id==='timeline-sort'){sort=e.target.value;listPage=0;render()}});

const DEMO_PINS=[['demo-1','Kibo Ramen','ramen',49.2797,-123.1218,'Granville St','Cozy bowls on rainy nights'],['demo-2','Purr & Pour Café','cafe',49.2844,-123.1089,'Gastown','Cats, coffee, and cinnamon buns'],['demo-3','Seawall Sushi','sushi',49.2888,-123.1307,'Coal Harbour','Omakase with a harbour view'],['demo-4','Matcha Moon','matcha',49.2765,-123.1303,'Yaletown','Soft serve and iced matcha'],['demo-5','Sweet Paws Dessert','dessert',49.2635,-123.1385,'Kitsilano','Pawprint cookies after a Kits walk']];
function demoDay(daysAgo){const d=new Date();d.setDate(d.getDate()-daysAgo);return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
const DEMO_VISITS=[
  ['visit-1','demo-1',1,'19:10','Dinner',4.5,'Tonkotsu with extra egg — cozy rainy night.'],
  ['visit-2','demo-5',2,'15:40','Dessert',5,'Pawprint cookies after a walk in Kits.'],
  ['visit-3','demo-2',3,'10:20','Cafe',4.8,'Oat latte and a warm cinnamon bun.'],
  ['visit-4','demo-3',5,'18:45','Dinner',4.2,'Omakase night by the water.'],
  ['visit-5','demo-4',8,'14:05','Cafe',4.6,'Iced matcha and soft serve in Yaletown.'],
  ['visit-6','demo-1',12,'12:30','Lunch',4,'Spicy miso for lunch — still thinking about it.'],
  ['visit-7','demo-3',18,'13:15','Lunch',4.3,'Salmon bowl on a sunny afternoon.']
];
function seedDemoPins(){
  if(state.restaurants.length||!(USER==='demo'||/github\.io$/.test(location.hostname)))return;
  const d=RL.today();
  state.restaurants=DEMO_PINS.map(([id,name,kind,lat,lng,address,note],i)=>({id,name,kind,lat,lng,address,tags:['demo'],note,wish:i%2===1,added:demoDay(20+i),rating:null,demo:true,preview:true,u:0}));
  if(!state.visits.length){
    state.visits=DEMO_VISITS.map(([id,restaurantId,ago,time,meal,rating,note])=>({id,restaurantId,date:demoDay(ago),time,meal,rating,note,photos:[],u:0}));
  }
  state.u=Date.now();
}
function bootApp(){
  seedDemoPins();
  document.body.classList.remove('locked');
  $('#app').hidden=false;
  selected=null;
  const pinned=state.restaurants.find(r=>Number.isFinite(r.lat));
  if(pinned){mapCenter=[pinned.lat,pinned.lng];mapZoom=14}
  renderAvatar();
  render();
}

/* lock screen wiring */
$$('#lmode button').forEach(b=>b.onclick=()=>setMode(b.dataset.m));
$('#rem').checked=REMEMBER;$('#rem').onchange=()=>{REMEMBER=$('#rem').checked;localStorage.setItem('rl.remember',REMEMBER?'1':'0')};
$('#un').value=localStorage.getItem('rl.lastUser')||'';
$('#uf').onsubmit=async e=>{
  e.preventDefault();const u=$('#un').value,p=$('#pw').value;$('#go').disabled=true;lockMsg(MODE==='reg'?'Signing up…':'Logging in…');
  try{
    if(MODE==='reg'){
      if(p.length<8)throw new Error('Password must be at least 8 characters');
      if(!$('#ack').checked)throw new Error('Please confirm you understand the password can’t be reset');
      await doRegister(u,p,$('#code').value.trim());
    }else{
      if(!p)throw new Error('Please enter your password');
      await doLogin(u,p);
    }
  }catch(err){lockMsg(err.message||String(err),true)}finally{$('#go').disabled=false}
};

(async function(){
  const v=await vault('get');
  if(!v||!v.key||!v.refresh)return;
  USER=v.user;SALT=v.salt;PASS=v.key;REFRESH=v.refresh;lockMsg('Signing you in…');
  try{await loadData()}catch(e){lockMsg(e.message||'Automatic sign-in failed',true);await vault('del')}
})();
