// Copyright 2026 Revetware LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {spawn} from 'node:child_process';
import {readFileSync,existsSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';

const [chrome,origin,idpa,idpb,spki,output]=process.argv.slice(2);
const credential=process.env.REVETSEC_SAML_FIXTURE_CREDENTIAL;
if(!credential||![origin,idpa,idpb].every(value=>/^https:\/\/(sp|idpa|idpb)\.example\.test:[0-9]+$/.test(value))||!/^[A-Za-z0-9+/]{43}=$/.test(spki))throw Error('Fixed private origins and leaf SPKI required');
const directory=mkdtempSync(join(tmpdir(),'revetsec-saml-browser-')),profile=join(directory,'profile');
const args=['--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--enable-automation','--user-data-dir='+profile,'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-sync','--disable-extensions','--no-proxy-server','--host-resolver-rules=MAP sp.example.test 127.0.0.1,MAP idpa.example.test 127.0.0.1,MAP idpb.example.test 127.0.0.1','--ignore-certificate-errors-spki-list='+spki,'about:blank'];
const browser=spawn(chrome,args,{stdio:['ignore','ignore','pipe']});let stderr='';browser.stderr.on('data',value=>{if(stderr.length<10000)stderr+=value.toString();});
let ws,session,closed=false;const pending=new Map();let sequence=0;const events=[];
browser.once('exit',()=>{closed=true;});
const receipt={success:false,scope:'Owned real headless Chrome+SAN TLS+synthetic IdPs; no hosted IdP, system trust, formal attack-tool or fleet recovery claim',globalTrustMutation:false,unscopedCertificateBypass:false,sandboxDisabled:false,checks:[],responses:[],blockedExternal:0,ownedBrowserStopped:false,ownedProfileRemoved:false};
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function wait(name,fn){const until=Date.now()+12000;while(Date.now()<until){try{if(await fn())return;}catch{}await delay(30);}throw Error('Timeout '+name);}
function check(name,value){receipt.checks.push({name,passed:Boolean(value)});if(!value)throw Error(name);}
function send(method,params={},sessionId){return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});}
async function evaluate(expression){const reply=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true},session);if(reply.exceptionDetails)throw Error('DOM evaluation');return reply.result.value;}
async function visit(url){await send('Page.navigate',{url},session);await wait('navigation',()=>evaluate('location.href==='+JSON.stringify(url)+'&&document.readyState==="complete"'));}
async function click(selector){check('button-'+selector,await evaluate('(()=>{let b=document.querySelector('+JSON.stringify(selector)+');if(!b)return false;b.click();return true})()'));}
async function json(path){return evaluate('(async()=>{let r=await fetch('+JSON.stringify(path)+');return {status:r.status,value:await r.json()}})()');}
async function current(){await visit(origin+'/saml/session');return evaluate('JSON.parse(document.body.textContent)');}
async function begin(mode,provider='idp-a'){
    await visit(origin+'/saml/home');await click('#bootstrap');await wait('controls',()=>evaluate('!!document.querySelector("#login-idp-a-redirect")'));
    const anonymous=await send('Network.getCookies',{urls:[origin]},session);const id=anonymous.cookies.find(c=>c.name==='__Host-saml-session');
    check('anonymous-cross-site-cookie-'+mode,id&&id.secure&&id.httpOnly&&id.sameSite==='None');
    await click('#login-'+provider+'-'+mode);
    if(mode==='post'){await wait('signed-sp-form',()=>evaluate('!!document.querySelector("form input[name=SAMLRequest]")'));await click('button[form=saml-post-form]');}
    await wait('idp-form',()=>evaluate('location.origin==='+JSON.stringify(provider==='idp-a'?idpa:idpb)+'&&!!document.querySelector("#continue")'));
    const jar=await send('Network.getCookies',{urls:[origin]},session);const pendingCookie=jar.cookies.find(c=>c.name==='__Host-saml-pending');
    check('cross-site-pending-cookie-'+mode,pendingCookie&&pendingCookie.secure&&pendingCookie.httpOnly&&pendingCookie.sameSite==='None');
    await click('#continue');await wait('sp-authenticated',()=>evaluate('location.origin==='+JSON.stringify(origin)+'&&location.pathname==="/saml/session"&&JSON.parse(document.body.textContent).authenticated===true'));
    const final=await send('Network.getCookies',{urls:[origin]},session);const auth=final.cookies.find(c=>c.name==='__Host-saml-session');
    check('real-browser-rotation-'+mode,auth&&id&&auth.value!==id.value&&auth.secure&&auth.httpOnly&&auth.sameSite==='Lax'&&!final.cookies.some(c=>c.name==='__Host-saml-pending'));
}
try{
    await wait('devtools',()=>existsSync(join(profile,'DevToolsActivePort')));const [port,path]=readFileSync(join(profile,'DevToolsActivePort'),'utf8').trim().split('\n');
    ws=new WebSocket('ws://127.0.0.1:'+port+path);await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
    ws.addEventListener('message',event=>{const value=JSON.parse(event.data);if(value.id){let promise=pending.get(value.id);pending.delete(value.id);if(promise){if(value.error)promise.reject(Error(value.error.message));else promise.resolve(value.result);}}else events.push(value);});
    receipt.version=await send('Browser.getVersion');const command=await send('Browser.getBrowserCommandLine');
    check('actual-browser-scoped-trust-and-sandbox',!command.arguments.includes('--no-sandbox')&&!command.arguments.includes('--ignore-certificate-errors')&&command.arguments.includes('--ignore-certificate-errors-spki-list='+spki));
    const {targetId}=await send('Target.createTarget',{url:'about:blank'});session=(await send('Target.attachToTarget',{targetId,flatten:true})).sessionId;
    await send('Page.enable',{},session);await send('Runtime.enable',{},session);await send('Network.enable',{},session);
    await send('Network.setExtraHTTPHeaders',{headers:{'X-Fixture-Credential':credential}},session);
    await send('Fetch.enable',{patterns:[{urlPattern:'*'}]},session);
    ws.addEventListener('message',event=>{const value=JSON.parse(event.data);if(value.method==='Fetch.requestPaused'&&value.sessionId===session){let url=value.params.request.url,allowed=[origin,idpa,idpb].some(o=>url.startsWith(o+'/'));if(!allowed)receipt.blockedExternal++;send(allowed?'Fetch.continueRequest':'Fetch.failRequest',allowed?{requestId:value.params.requestId}:{requestId:value.params.requestId,errorReason:'BlockedByClient'},session).catch(()=>{});}});
    await visit(origin+'/saml/home');let initial=await json('/saml/fixture/state');check('browser-get-no-allocation',initial.value.host.sessions===0);
    await begin('redirect');let protectedReply=await json('/saml/account/tenant/alice');check('browser-current-policy-data',protectedReply.status===200&&protectedReply.value.access==='permitted');
    for(const mode of ['post','redirect']){
        await visit(origin+'/saml/home');await click('#bootstrap');await wait('logout-controls',()=>evaluate('!!document.querySelector("#logout-'+mode+'")'));await click('#logout-'+mode);
        if(mode==='post'){await wait('sp-logout-form',()=>evaluate('!!document.querySelector("form input[name=SAMLRequest]")'));await click('button[form=saml-post-form]');await wait('idp-logout-form',()=>evaluate('location.origin==='+JSON.stringify(idpa)+'&&!!document.querySelector("#continue")'));await click('#continue');}
        await wait('logout-return',()=>evaluate('location.origin==='+JSON.stringify(origin)+'&&location.pathname==="/saml/logout-return/'+mode+'"&&document.body.textContent.includes("provider_logout_reported")'));
        const jar=await send('Network.getCookies',{urls:[origin]},session);check('browser-local-first-logout-'+mode,!jar.cookies.some(c=>c.name==='__Host-saml-session'||c.name==='__Host-saml-logout'));
        check('browser-logout-no-revival-'+mode,(await current()).authenticated===false);
        if(mode==='post')await begin('post');
    }
    await json('/saml/fixture/idp-no-referrer');await begin('post','idp-b');await visit(origin+'/saml/home');await click('#bootstrap');await wait('local-controls',()=>evaluate('!!document.querySelector("#logout-local")'));await click('#logout-local');await wait('local-ended',()=>evaluate('JSON.parse(document.body.textContent).authenticated===false'));
    const final=await json('/saml/fixture/state');check('actual-signed-requests-observed',final.value.signed_requests_verified>=5&&final.value.saved>=5&&final.value.consumed>=5);check('browser-no-authenticated-session',final.value.host.authenticated_sessions===0);check('actual-null-origin-still-requires-signed-bound-flow',events.some(e=>e.method==='Network.requestWillBeSent'&&new URL(e.params.request.url).pathname==='/saml/acs'&&e.params.request.headers.Origin==='null'));
    receipt.requestFacts=events.filter(e=>e.method==='Network.requestWillBeSent').map(e=>({origin:new URL(e.params.request.url).origin,path:new URL(e.params.request.url).pathname,method:e.params.request.method,originHeader:e.params.request.headers.Origin,contentType:e.params.request.headers['Content-Type'],bodyLength:e.params.request.postData?.length}));
    receipt.responses=events.filter(e=>e.method==='Network.responseReceived').map(e=>({origin:new URL(e.params.response.url).origin,path:new URL(e.params.response.url).pathname,status:e.params.response.status,protocol:e.params.response.protocol,securityState:e.params.response.securityState,certificate:e.params.response.securityDetails?{protocol:e.params.response.securityDetails.protocol,subject:e.params.response.securityDetails.subjectName,san:e.params.response.securityDetails.sanList}:null}));
    check('real-san-tls-observed',receipt.responses.some(r=>r.certificate&&r.certificate.san.includes('sp.example.test')&&r.certificate.protocol.startsWith('TLS')));
    receipt.success=true;
}catch(failure){receipt.failure={type:failure.name,message:failure.message};receipt.stderr=stderr.slice(-1000);try{receipt.current=await evaluate('({origin:location.origin,path:location.pathname,title:document.title,bodyLength:document.body.textContent.length,jsonKeys:(()=>{try{return Object.keys(JSON.parse(document.body.textContent))}catch{return []}})()})');}catch{}}
finally{
    receipt.requestFacts=events.filter(e=>e.method==='Network.requestWillBeSent').map(e=>({origin:new URL(e.params.request.url).origin,path:new URL(e.params.request.url).pathname,method:e.params.request.method,originHeader:e.params.request.headers.Origin,contentType:e.params.request.headers['Content-Type'],bodyLength:e.params.request.postData?.length}));
    receipt.responses=events.filter(e=>e.method==='Network.responseReceived').map(e=>({origin:new URL(e.params.response.url).origin,path:new URL(e.params.response.url).pathname,status:e.params.response.status,securityState:e.params.response.securityState,certificate:e.params.response.securityDetails?{protocol:e.params.response.securityDetails.protocol,san:e.params.response.securityDetails.sanList}:null}));
    if(ws){try{await send('Browser.close');}catch{}ws.close();}
    for(let i=0;i<50&&!closed;i++)await delay(20);if(!closed){browser.kill('SIGTERM');for(let i=0;i<50&&!closed;i++)await delay(20);}if(!closed){browser.kill('SIGKILL');await delay(100);}
    receipt.ownedBrowserStopped=closed;rmSync(directory,{recursive:true,force:true});receipt.ownedProfileRemoved=!existsSync(directory);receipt.success&&=receipt.ownedBrowserStopped&&receipt.ownedProfileRemoved;
    writeFileSync(output,JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify({success:receipt.success,checks:receipt.checks.length,failure:receipt.failure}));
}
process.exitCode=receipt.success?0:1;
