"""Deterministic source ZIP, no credentials, venv or local test artifacts."""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
import hashlib,json
root=Path(__file__).resolve().parent.parent
out=root/'artifacts'/'deploy.zip';out.parent.mkdir(exist_ok=True)
files=sorted([p for p in (root/'app').rglob('*') if p.is_file() and '__pycache__' not in str(p)]+[root/'requirements.txt',root/'.deployment'])
with ZipFile(out,'w',ZIP_DEFLATED) as z:
 for p in files:z.write(p,p.relative_to(root))
(root/'artifacts'/'source-manifest.json').write_text(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},indent=2)+'\n')
print(out)
