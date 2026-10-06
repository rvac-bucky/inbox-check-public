'use strict';
const $=id=>document.getElementById(id);let current=null,me=null,selected=null,busy=false;
let joinCode=null,joining=false,creatingShared=false,reviewerMode=false;
const verdicts={likely_phishing:{color:'red',label:'🔴 RED — Do not act on this message',detail:'Do not reply, pay, share codes, or use its links until independently verified.'},suspicious:{color:'yellow',label:'🟡 YELLOW — Warning signs',detail:'Pause and verify the request through a contact you already trust.'},insufficient_evidence:{color:'yellow',label:'🟡 YELLOW — Unable to assess',detail:'We could not complete a reliable assessment. Do not treat this as a safe result.'},no_obvious_warning_signs:{color:'green',label:'🟢 GREEN — No obvious warning signs',detail:'No clear warning signs in the supplied content. This does not verify the sender or links.'}};
const verdictOf=r=>verdicts[r]||verdicts.suspicious;
let noticeTimer;
function notice(message){$('notice').textContent=message;$('notice').hidden=false;clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>$('notice').hidden=true,10000);}
async function api(path,method='GET',body=null){let options={method,credentials:'same-origin',headers:{'X-Inbox-Request':'1'}};if(body instanceof FormData)options.body=body;else if(body!==null){options.headers['Content-Type']='application/json';options.body=JSON.stringify(body)}const response=await fetch('/api'+path,options);let result;try{result=await response.json()}catch{throw Error('Service unavailable. Please try again shortly.')}if(!response.ok){if(response.status===401&&path!='/login'){me=null;$('workspace').hidden=true;$('login').hidden=false;}throw Error(result.detail||'The request could not be completed.')}return result;}
function view(id){document.querySelector('.intro').hidden=['result','working'].includes(id);if(id==='result')requestAnimationFrame(()=>$('result').scrollIntoView({block:'start'}));['intake','working','result','queue'].forEach(x=>$(x).hidden=x!==id);$('newtab').classList.toggle('selected',id!=='queue');$('queuetab').classList.toggle('selected',id==='queue');}
async function init(){try{const config=await api('/config');Object.assign(verdicts,config.verdicts);if($('sitename'))$('sitename').textContent=config.site_name;document.title=config.site_name;}catch{}try{try{me=await api('/me');}catch{if(reviewerMode||joinCode)throw 0;await api('/guest','POST',{});me=await api('/me');}$('login').hidden=true;$('workspace').hidden=false;$('logout').hidden=false;$('invitebox').hidden=me.role!=='reviewer';$('sessionlabel').textContent='Private session: '+me.name+'. Sign out before another person uses this browser.';}catch{$('login').hidden=false;return;}$('login').hidden=true;loadMail();}
$('reviewersignin').onclick=()=>{reviewerMode=true;$('workspace').hidden=true;$('login').hidden=false;$('personal-login').hidden=false;$('loginform').hidden=false;$('joinform').hidden=true;$('login').scrollIntoView();};
$('loginform').onsubmit=async e=>{e.preventDefault();try{await api('/login','POST',{code:$('code').value.trim()});$('code').value='';await init();}catch(e){notice(e.message)}};
$('joinform').onsubmit=async e=>{
 e.preventDefault();if(joining)return;
 if(!joinCode||!$('joinconsent').checked||!$('joinname').value.trim()){notice('Enter a display name and confirm sanitized use.');return;}
 joining=true;$('joinbutton').disabled=true;
 try{await api('/join','POST',{code:joinCode,name:$('joinname').value.trim(),consent:true});await init();view('intake');}
 catch(e){notice(e.message)}finally{joining=false;$('joinbutton').disabled=false;}
};
$('logout').onclick=async()=>{try{await api('/logout','POST',{});location.reload()}catch(e){notice(e.message)}};
function file(f){if(busy)return;if(f.size>8*1024*1024){notice('Choose a file no larger than 8 MB.');return;}selected=f;$('filename').textContent=f.name;$('fileinfo').hidden=false;$('message').value='';$('message').disabled=true;view('intake');}
$('choose').onclick=e=>{e.stopPropagation();$('file').click()};$('dropzone').onclick=()=>$('file').click();$('dropzone').onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file').click()}};$('file').onchange=()=>{if($('file').files[0])file($('file').files[0])};
$('removefile').onclick=()=>{selected=null;$('file').value='';$('fileinfo').hidden=true;$('message').disabled=false;};
for(const type of ['dragenter','dragover'])$('dropzone').addEventListener(type,e=>{e.preventDefault();e.stopPropagation();$('dropzone').classList.add('drag')});
$('dropzone').addEventListener('dragleave',e=>{e.preventDefault();$('dropzone').classList.remove('drag')});
$('dropzone').addEventListener('drop',e=>{e.preventDefault();e.stopPropagation();$('dropzone').classList.remove('drag');if(e.dataTransfer.files.length!==1){notice('Drop one file at a time.');return;}file(e.dataTransfer.files[0])});
document.addEventListener('dragover',e=>{if(e.dataTransfer)e.preventDefault()});
document.addEventListener('drop',e=>{e.preventDefault();if(e.dataTransfer&&e.dataTransfer.files.length)notice('Drop the file inside the box.')});
document.addEventListener('paste',e=>{if(!me||busy)return;const image=Array.from(e.clipboardData.items).find(x=>x.kind==='file'&&x.type.startsWith('image/'));if(image){e.preventDefault();const f=image.getAsFile();file(new File([f],'pasted-screenshot.'+(f.type==='image/jpeg'?'jpg':f.type==='image/webp'?'webp':'png'),{type:f.type}));}});
$('analyze').onclick=async()=>{if(busy)return;if(!$('consent').checked){notice('Confirm this is sanitized pilot data before submitting.');return;}if(!selected&&$('message').value.trim().length<20){notice('Paste the email text or choose a screenshot first.');return;}let form=new FormData();form.append('consent','yes');if(selected)form.append('file',selected);else form.append('text',$('message').value);busy=true;view('working');try{render(await api('/analyze','POST',form));}catch(e){view('intake');notice(e.message)}finally{busy=false;}};
function fillList(id,items){$(id).replaceChildren(...items.map(t=>{let li=document.createElement('li');li.textContent=t;return li;}));}
function explanationStatus(p){
 if(!p.explanation_fallback)return 'Screening complete.';
 const reason=p.explanation_status?.reason;
 const reasons={legacy_guidance:'This earlier assessment uses updated guidance; submit it again for the new classification rules.',provider_timeout:'The detailed explanation timed out.',provider_rate_limited:'The explanation provider is temporarily rate-limiting requests.',provider_auth:'The explanation service has an access problem.',provider_unavailable:'The explanation service could not complete its request.',invalid_response:'The detailed explanation did not meet our response requirements.',incomplete_response:'The explanation provider returned an incomplete response.',safety_rejected:'The detailed explanation did not pass our wording checks.',content_filtered:'Part of the check was blocked by a processing filter. This is not proof of malicious intent; verify independently.',not_recorded:'The detailed explanation was not available; this earlier version did not record why.'};
 if(reason==='content_filtered')return 'Screening complete. '+reasons.content_filtered;
 return 'Screening complete · Basic guidance shown. '+(reasons[reason]||reasons.not_recorded)+' Your verdict is unchanged.';
}
function render(c){current=c;const p=c.payload,a=p.assessment;{const v=verdictOf(a.risk);$('verdict').textContent=v.label;$('verdict').className='verdict v-'+v.color;$('verdictdetail').textContent=v.detail;}$('type').textContent=a.message_type;$('summary').textContent=p.explanation.summary;$('analysisstatus').textContent=explanationStatus(p);$('agentreply').hidden=true;$('agenttext').textContent='';$('signals').replaceChildren(...a.signals.filter(s=>s.strength!=='not_observed').map(s=>{let span=document.createElement('span');span.className='signal';span.textContent=s.label+' · '+s.strength;return span;}));fillList('evidence',p.explanation.evidence.length?p.explanation.evidence:['No specific evidence is available in this explanation.']);fillList('steps',p.explanation.next_steps);$('limits').textContent=p.explanation.limitations;$('extracted').textContent=p.text;$('share').hidden=!c.owned||c.shared;$('delete').hidden=!c.owned;$('reviewform').hidden=!(me.role==='reviewer'&&c.shared);$('reviewnote').value='';$('humanreview').hidden=!p.review;if(p.review){$('reviewtext').textContent=p.review.note;$('reviewby').textContent=p.review.reviewer+' · '+new Date(p.review.at*1000).toLocaleString();}$('provenance').textContent='Inbox Check · '+p.seconds+'s · expires '+new Date(c.expires*1000).toLocaleString();view('result');}
async function queue(){if(busy){notice('An analysis is still in progress.');return;}try{const {cases}=await api('/cases');$('count').textContent=cases.length||'';$('caselist').replaceChildren();if(!cases.length){let p=document.createElement('p');p.textContent='No cases yet. Check a message to get started.';$('caselist').append(p);}for(const c of cases){let btn=document.createElement('button');btn.className='case';let title=document.createElement('div');title.textContent=verdictOf(c.risk).label;let date=document.createElement('small');date.textContent=new Date(c.created*1000).toLocaleString();title.append(date);let state=document.createElement('span');state.textContent=c.reviewed?'Reviewed':c.shared?'Shared for review':'Private';btn.append(title,state);btn.onclick=async()=>{try{render(await api('/cases/'+c.id))}catch(e){notice(e.message)}};$('caselist').append(btn);}view('queue');if(me.role==='reviewer')await loadSharedLinks();}catch(e){notice(e.message)}}
$('queuetab').onclick=queue;$('refresh').onclick=queue;$('newtab').onclick=()=>{if(!busy)view('intake')};$('again').onclick=()=>{selected=null;current=null;$('file').value='';$('filename').textContent='';$('fileinfo').hidden=true;$('message').value='';$('message').disabled=false;$('consent').checked=false;view('intake');$('message').focus();};
$('share').onclick=async()=>{if(!current)return;try{await api('/cases/'+current.id+'/share','POST',{});render(await api('/cases/'+current.id));notice('Shared with the security review team.');}catch(e){notice(e.message)}};
$('delete').onclick=async()=>{if(!current||!confirm('Delete this case and its extracted content?'))return;try{await api('/cases/'+current.id+'/delete','POST',{});current=null;await queue();notice('Case deleted.');}catch(e){notice(e.message)}};
$('savereview').onclick=async()=>{try{await api('/cases/'+current.id+'/review','POST',{note:$('reviewnote').value});render(await api('/cases/'+current.id));notice('Human review recorded.');}catch(e){notice(e.message)}};
$('export').onclick=()=>{const p=current.payload;const text=[document.title,verdictOf(p.assessment.risk).label,explanationStatus(p),p.explanation.summary,'',...p.explanation.evidence,'','Next steps:',...p.explanation.next_steps,'','Not a safety certificate. Sender, links and attachments have not been verified.',p.review?'Human review: '+p.review.note:'No human review recorded.'].join('\n');const url=URL.createObjectURL(new Blob([text],{type:'text/plain'}));const a=document.createElement('a');a.href=url;a.download='inbox-check-report.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
let inviting=false,inviteCount=0;
function showInvite(name,code){
 const row=document.createElement('div');row.className='invite-result';
 const label=document.createElement('label');const input=document.createElement('input');
 input.id='created-invite-'+(++inviteCount);input.readOnly=true;input.value=(me.invite_origin||location.origin)+'/#invite='+encodeURIComponent(code);
 input.autocomplete='off';input.spellcheck=false;label.htmlFor=input.id;label.textContent=name;
 const copy=document.createElement('button');copy.type='button';copy.className='secondary';copy.textContent='Copy link';copy.setAttribute('aria-label','Copy invite for '+name);
 copy.onclick=async()=>{try{await navigator.clipboard.writeText(input.value);notice('Invitation copied for '+name+'.');}catch{input.focus();input.select();notice('Copy the selected link for '+name+'.');}};
 const controls=document.createElement('div');controls.className='invite-controls';controls.append(input,copy);row.append(label,controls);$('inviteresults').append(row);
 $('invitelink').hidden=false;$('addmore').hidden=false;
}
$('addmore').onclick=()=>{$('invitename').focus();$('invitename').scrollIntoView({block:'center',behavior:'smooth'});};
$('invite').onclick=async()=>{
 if(inviting)return;
 const names=$('invitename').value.split(/\r?\n/).map(n=>n.trim()).filter(Boolean);
 if(!names.length){notice('Enter at least one participant name.');$('invitename').focus();return;}
 if(names.length>20||names.some(n=>n.length>80)){notice('Use up to 20 names per batch, with no more than 80 characters per name.');return;}
 if(new Set(names.map(n=>n.toLowerCase())).size!==names.length){notice('Each name in this batch must be distinct. Add an initial if two people have the same name.');return;}
 inviting=true;let created=0;$('invite').disabled=true;$('invitename').disabled=true;$('addmore').disabled=true;
 try{
  for(const name of names){
   $('invitestatus').textContent='Creating invitation '+(created+1)+' of '+names.length+'…';
   const d=await api('/invites','POST',{name,role:'submitter'});
   showInvite(name,d.code);created++;
   $('invitename').value=names.slice(created).join('\n');
  }
  $('invitestatus').textContent=created+' invitation'+(created===1?'':'s')+' created. Copy the links below, or add more people.';
 }catch(e){$('invitestatus').textContent=created+' of '+names.length+' invitations created. Existing links are kept; remaining names are still in the box. '+e.message;}
 finally{inviting=false;$('invite').disabled=false;$('invitename').disabled=false;$('addmore').disabled=false;if(created===names.length)$('invitename').focus();}
};
async function loadSharedLinks(){
 try{
  const d=await api('/enrollment-links');$('sharedlinks').replaceChildren();
  for(const link of d.links){
   const row=document.createElement('div');row.className='invite-result';
   const title=document.createElement('p');title.textContent=link.label+' · '+link.joins+' guest session'+(link.joins===1?'':'s')+' started · '+(link.enabled?'expires '+new Date(link.expires*1000).toLocaleDateString():'disabled');row.append(title);
   if(link.enabled){
    const input=document.createElement('input');input.readOnly=true;input.value=(me.invite_origin||location.origin)+'/#join='+encodeURIComponent(link.code);input.setAttribute('aria-label','Reusable signup link');
    const copy=document.createElement('button');copy.type='button';copy.className='secondary';copy.textContent='Copy signup link';
    copy.onclick=async()=>{try{await navigator.clipboard.writeText(input.value);notice('Copied. You can send this same signup link to multiple people.');}catch{input.focus();input.select();notice('Copy the selected signup link.');}};
    const revoke=document.createElement('button');revoke.type='button';revoke.className='quiet danger';revoke.textContent='Disable link';
    revoke.onclick=async()=>{if(!confirm('Stop new signups through this link? Existing private sessions remain active.'))return;revoke.disabled=true;try{await api('/enrollment-links/'+link.id+'/revoke','POST',{});await loadSharedLinks();notice('Link disabled for new signups.');}catch(e){notice(e.message);revoke.disabled=false;}};
    const controls=document.createElement('div');controls.className='invite-controls wrap';controls.append(input,copy,revoke);row.append(controls);
   }
   $('sharedlinks').append(row);
  }
  $('sharedstatus').textContent=d.links.length?'Your existing links stay available here after a refresh.':'No shared signup links yet.';
 }catch(e){$('sharedstatus').textContent='Shared links could not be loaded. '+e.message;}
}
$('createshared').onclick=async()=>{
 if(creatingShared)return;creatingShared=true;$('createshared').disabled=true;
 try{await api('/enrollment-links','POST',{label:'Pilot signup'});await loadSharedLinks();notice('Signup link created. Copy it and share with your testers.');}
 catch(e){notice(e.message)}finally{creatingShared=false;$('createshared').disabled=false;}
};
const fragment=new URLSearchParams(location.hash.slice(1));
if(fragment.has('invite')){
 $('code').value=fragment.get('invite');try{sessionStorage.removeItem('inboxcheck_join');}catch{}history.replaceState(null,'',location.pathname);
}else{
 try{joinCode=fragment.has('join')?fragment.get('join'):sessionStorage.getItem('inboxcheck_join');if(joinCode)sessionStorage.setItem('inboxcheck_join',joinCode);}catch{joinCode=fragment.get('join');}
 if(joinCode){$('joinform').hidden=false;$('loginform').hidden=true;$('personal-login').hidden=true;}
 if(fragment.has('join'))history.replaceState(null,'',location.pathname);
}
async function loadMail(){try{const m=await api('/mail-link');if(!m.enabled)return;$('mailbox').hidden=false;$('mailaddr').textContent=m.mailbox;}catch{}}
init();
