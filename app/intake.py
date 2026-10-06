"""Deterministically bounded ingress. No uploaded file may roll to disk."""
import asyncio,time
from contextlib import asynccontextmanager
from fastapi import HTTPException
from starlette.formparsers import MultiPartParser,FormParser,MultiPartException,parse_options_header
from .core import MAX_FILE, MAX_TEXT
MAX_BODY=MAX_FILE+65536
BODY_IDLE_SECONDS=5.0
BODY_TOTAL_SECONDS=15.0

class Limits:
    def __init__(self,app):self.app=app;self.active=0
    async def __call__(self,scope,receive,send):
        if scope['type']!='http' or scope['method'] in ('GET','HEAD','OPTIONS'):
            return await self.app(scope,receive,send)
        if self.active>=16:
            from starlette.responses import JSONResponse
            return await JSONResponse({'detail':'Service busy; try shortly.'},429)(scope,receive,send)
        self.active+=1;total=0;started=time.monotonic()
        limit=MAX_BODY if scope['path']=='/api/analyze' else 262144 if scope['path']=='/api/agent/analyze' else 32768
        async def bounded():
            nonlocal total
            remaining=BODY_TOTAL_SECONDS-(time.monotonic()-started)
            if remaining<=0:raise HTTPException(408,'Request body timed out.')
            try:msg=await asyncio.wait_for(receive(),min(BODY_IDLE_SECONDS,remaining))
            except TimeoutError:raise HTTPException(408,'Request body timed out.') from None
            total+=len(msg.get('body',b''))
            if total>limit:raise HTTPException(413,'Request body exceeds its limit.')
            return msg
        try:await self.app(scope,bounded,send)
        finally:self.active-=1

class MemoryMultipart(MultiPartParser):
    # Receive middleware rejects the request BEFORE a chunk can exceed MAX_BODY.
    # A single file can therefore never reach this rollover threshold.
    spool_max_size=MAX_BODY
    def on_part_begin(self):
        self.header_bytes=0;super().on_part_begin()
    def on_header_field(self,data,start,end):
        self.header_bytes+=end-start
        if self.header_bytes>8192:raise MultiPartException('Part headers too large.')
        super().on_header_field(data,start,end)
    def on_header_value(self,data,start,end):
        self.header_bytes+=end-start
        if self.header_bytes>8192:raise MultiPartException('Part headers too large.')
        super().on_header_value(data,start,end)

@asynccontextmanager
async def memory_form(request):
    form=None
    try:
        content_type=request.headers.get('content-type','')
        if len(content_type)>512:raise MultiPartException('Invalid content type.')
        kind,params=parse_options_header(content_type)
        if kind==b'multipart/form-data':
            if not 1<=len(params.get(b'boundary',b''))<=70:raise MultiPartException('Invalid multipart boundary.')
            parser=MemoryMultipart(request.headers,request.stream(),max_files=1,max_fields=3,max_part_size=MAX_TEXT*4+1024)
        elif kind==b'application/x-www-form-urlencoded':
            parser=FormParser(request.headers,request.stream(),max_fields=3,max_part_size=MAX_TEXT*4+1024)
        else:raise MultiPartException('Use a text or file form.')
        form=await parser.parse()
        keys=[k for k,v in form.multi_items()]
        if len(set(keys))!=len(keys) or set(keys)-{'text','consent','file'}:
            raise MultiPartException('Invalid or duplicate fields.')
        yield form
    except MultiPartException:
        raise HTTPException(400,'Invalid or oversized message form.') from None
    finally:
        if form is not None:await form.close()
