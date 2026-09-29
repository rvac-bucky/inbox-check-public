"""Disposable resource-bounded parser process. Input never touches disk."""
import base64,codecs,json,resource,sys
if sys.platform.startswith('linux'):
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(8,8))
try:
    from .core import extract_file,MAX_FILE,Image,FILE_REJECTIONS
    # Load codecs and optional PDF parser before filesystem/network access is denied.
    Image.init()
    for encoding in ('utf-8-sig','ascii','latin-1','cp1252','utf-16','utf-16-le','utf-16-be'):
        codecs.lookup(encoding)
    if sys.argv[1].lower().endswith('.pdf'):
        import pypdf
    if sys.argv[1].lower().endswith('.msg'):
        import olefile
    from .parser_sandbox import restrict
    try:sandbox=restrict()
    except Exception:
        print(json.dumps({'error_code':'parser_sandbox'}));sys.exit(2)
    data=sys.stdin.buffer.read(MAX_FILE+1)
    text,image,source=extract_file(data,sys.argv[1])
    print(json.dumps({'text':text,'image':base64.b64encode(image).decode() if image else None,'source':source,'sandbox':sandbox}))
except ModuleNotFoundError:
    print(json.dumps({'error_code':'parser_dependency'}));sys.exit(2)
except MemoryError:
    print(json.dumps({'error_code':'parser_memory'}));sys.exit(2)
except Exception as e:
    # Fixed labels only, never parser exception text or submitted content.
    if type(e).__name__=='InputError' and str(e) in FILE_REJECTIONS:
        print(json.dumps({'error_code':'input_rejected','message':str(e)}));sys.exit(2)
    print(json.dumps({'error_code':'parser_fault'}));sys.exit(2)
