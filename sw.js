/* Meowsto service worker (ui20261015el) — Web Push only.
   No fetch handler on purpose: every request goes to the network exactly as before (no caching, ?v= busting unchanged). */
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
const SCOPE=()=>self.registration.scope;
function inScope(u){try{const x=new URL(u,SCOPE());return x.href.startsWith(SCOPE())?x.href:null}catch{return null}}
self.addEventListener('push',e=>{
  let d={};try{d=e.data?e.data.json():{}}catch{d={body:e.data?e.data.text():''}}
  const url=inScope(d.url)||SCOPE();
  e.waitUntil(self.registration.showNotification(String(d.title||'Meowsto 🐾'),{
    body:String(d.body||'New place — tap to open'),
    icon:SCOPE()+'assets/icon-192.png',badge:SCOPE()+'assets/icon-192.png',
    tag:String(d.tag||'meowsto-inbox'),data:{url,id:d.id?String(d.id):null}}));
});
self.addEventListener('notificationclick',e=>{
  e.notification.close();
  const {url,id}=e.notification.data||{};
  e.waitUntil((async()=>{
    const list=await self.clients.matchAll({type:'window',includeUncontrolled:true});
    const c=list.find(w=>w.url.startsWith(SCOPE()));
    if(c){try{await c.focus()}catch{}c.postMessage({type:'meowsto-inbox',id});return}
    await self.clients.openWindow(inScope(url)||SCOPE());
  })());
});
