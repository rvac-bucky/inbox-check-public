"""Local-only synthetic browser test server, never imported by deployment."""
import os,tempfile,sys
from cryptography.fernet import Fernet
os.environ.update(DATA_ENCRYPTION_KEY=Fernet.generate_key().decode(),DB_PATH=tempfile.mkdtemp(prefix='inboxcheck-preview-')+'/cases.db',LOCAL_DEV='1',PUBLIC_ORIGIN='http://127.0.0.1:8094',BOOTSTRAP_KEY='local-test-only')
from app.main import app
from tests.test_app import Fake
old=app.router.lifespan_context
from contextlib import asynccontextmanager
@asynccontextmanager
async def preview(app):
    async with old(app):
        app.state.models=Fake()
        if os.environ.get('PREVIEW_EXPLANATION_FAILURE'):
            from app.core import ProviderError
            def fail(*args):raise ProviderError('Synthetic failure','safety_rejected')
            app.state.models.explain=fail
        yield
app.router.lifespan_context=preview
if __name__=='__main__':
 import uvicorn
 uvicorn.run(app,host='127.0.0.1',port=8094,access_log=False)
