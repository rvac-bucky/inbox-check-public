(async()=>{
 const checks=[];const check=(ok,label)=>{if(!ok)throw Error(label);checks.push(label);};
 let calls=[],failAt=0,serial=0,copied='';
 window.fetch=async(path,options={})=>{
  if(path==='/api/me')return {ok:true,json:async()=>({name:'Synthetic reviewer',role:'reviewer'})};
  if(path==='/api/enrollment-links')return {ok:true,json:async()=>({links:[]})};
  if(path==='/api/cases')return {ok:true,json:async()=>({cases:[]})};
  if(path==='/api/invites'){
   const body=JSON.parse(options.body);calls.push(body);
   await new Promise(r=>setTimeout(r,30));
   if(failAt===calls.length)return {ok:false,status:429,json:async()=>({detail:'Synthetic invite limit reached'})};
   return {ok:true,json:async()=>({code:'synthetic-only-'+(++serial)})};
  }
  throw Error('Unexpected request '+path);
 };
 Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{copied=text;}}});
 await init();await queue();
 const input=document.getElementById('invitename'),button=document.getElementById('invite'),results=document.getElementById('inviteresults');
 input.value='Alex Taylor\nSam Lee\nMorgan Patel';
 const first=button.onclick();button.onclick();await first;
 check(calls.length===3,'double-submit blocked');
 check(calls.every(c=>c.role==='submitter'),'all invitations submitter-only');
 check(results.children.length===3&&input.value==='','batch creates three retained links and clears input');
 check(new Set([...results.querySelectorAll('input')].map(x=>x.value)).size===3,'each person gets a unique link');
 await results.querySelector('button').onclick();check(copied.endsWith('synthetic-only-1'),'copy selects correct participant link');
 document.getElementById('addmore').click();check(document.activeElement===input,'add-more focuses names');
 input.value='Fourth participant';await button.onclick();check(results.children.length===4,'add more retains previous links without reload');
 await queue();check(results.children.length===4,'queue refresh preserves created links');
 const n=calls.length;input.value='Repeat\nrepeat';await button.onclick();check(calls.length===n,'duplicate names rejected before writes');
 input.value=Array.from({length:21},(_,i)=>'Person '+i).join('\n');await button.onclick();check(calls.length===n,'oversized batch rejected');
 input.value='x'.repeat(81);await button.onclick();check(calls.length===n,'overlong name rejected');
 input.value='  \n ';await button.onclick();check(calls.length===n,'empty batch rejected');
 failAt=calls.length+2;input.value='First pending\nSecond pending\nThird pending';await button.onclick();
 check(results.children.length===5&&input.value==='Second pending\nThird pending','partial failure preserves successes and pending names');
 check(!button.disabled&&!input.disabled,'controls restored after failure');
 failAt=0;await button.onclick();check(results.children.length===7,'retry creates only remaining invitations');
 input.value='<img src=x onerror=alert(1)>';await button.onclick();check(results.children.length===8&&!results.querySelector('img'),'untrusted name rendered only as text');
 Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied')}}});
 const link=results.querySelector('input');await results.querySelector('button').onclick();check(document.activeElement===link&&link.selectionEnd===link.value.length,'clipboard denial selects link for manual copy');
 check(!localStorage.length&&!sessionStorage.length,'no invitation persistence in browser storage');
 document.getElementById('notice').hidden=true;
 return {passed:checks.length,checks};
})()
