#!/usr/bin/env python3
"""Opt-in synthetic evaluation of a specified running app; never reads production cases."""
import argparse,json,time
from pathlib import Path
import httpx
p=argparse.ArgumentParser();p.add_argument('--origin',required=True);p.add_argument('--output',required=True);p.add_argument('--limit',type=int);args=p.parse_args()
rows=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/screening_corpus.json').read_text())
if args.limit:rows=rows[:args.limit]
results=[]
with httpx.Client(base_url=args.origin,headers={'Origin':args.origin,'X-Inbox-Request':'1'},timeout=200) as c:
 c.post('/api/guest',json={}).raise_for_status()
 try:
  for index,row in enumerate(rows):
   # Separate synthetic test identities, within each identity's normal hourly cap.
   if index and index%7==0:
    c.post('/api/logout',json={}).raise_for_status();c.post('/api/guest',json={}).raise_for_status()
   started=time.monotonic();r=c.post('/api/analyze',data={'consent':'yes','text':row['text']})
   item={'id':row['id'],'accepted':row['accepted'],'http':r.status_code,'seconds':round(time.monotonic()-started,2)}
   if r.status_code==200:
    d=r.json();body=d['payload'];item.update(risk=body['assessment']['risk'],matched=body['assessment']['risk'] in row['accepted'],explanation_fallback=body.get('explanation_fallback'),explanation=body['explanation'])
    item['cleanup_http']=c.post('/api/cases/'+d['id']+'/delete',json={}).status_code
   else:item.update(matched=False,error=r.text[:300])
   results.append(item);Path(args.output).write_text(json.dumps(results,indent=2)+'\n')
   print(json.dumps({k:v for k,v in item.items() if k not in ('explanation','error')}),flush=True)
 finally:c.post('/api/logout',json={})
raise SystemExit(0 if all(x.get('matched') and x.get('cleanup_http')==200 for x in results) else 1)
