#!/usr/bin/env python3
"""Stage a pinned public-only website over an unchanged private base runtime.

No environment, current symlink, DNS or service is changed by this helper.
"""
import argparse, hashlib, io, json, os, re, shutil, tarfile, urllib.request
from pathlib import Path, PurePosixPath

REPO='soldabania-art/averkron-transfer-20261021'
BASE_REF='67c260aaa06c60c65b1c0f7c6ba2bd047308985a'
BASE=Path('/srv/averkron/releases/20261026-67c260a')
def digest(b): return hashlib.sha256(b).hexdigest()
def fetch(commit,prefix,name,limit):
    url=f'https://raw.githubusercontent.com/{REPO}/{commit}/{prefix}/{name}'
    with urllib.request.urlopen(url,timeout=45) as response: data=response.read(limit+1)
    if len(data)>limit: raise ValueError('Download too large')
    return data
def validate(raw,expected,source,archive):
    if digest(raw)!=expected: raise ValueError('Manifest checksum mismatch')
    m=json.loads(raw)
    if m['format']!='averkron-public-site-v1' or m['sourceRef']!=source or m['baseRuntimeRef']!=BASE_REF: raise ValueError('Wrong source')
    if digest(archive)!=m['archiveSha256'] or len(archive)!=m['archiveBytes']: raise ValueError('Archive mismatch')
    wanted=m['files']
    if not 1<=len(wanted)<=4096: raise ValueError('File count')
    found={};total=0
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
        for item in tar:
            p=PurePosixPath(item.name)
            if not item.isfile() or p.is_absolute() or str(p)!=item.name or len(p.parts)<2 or p.parts[0]!='public' or any(x in ('','..','__qa__') or x.startswith('.') for x in p.parts): raise ValueError('Unsafe public archive')
            if item.name in found or item.size>16*1024*1024: raise ValueError('Duplicate/large file')
            b=tar.extractfile(item).read();total+=len(b)
            if total>128*1024*1024: raise ValueError('Expanded archive too large')
            if wanted.get(item.name)!={'bytes':len(b),'sha256':digest(b)}: raise ValueError('Public file checksum')
            found[item.name]=b
    if set(found)!=set(wanted): raise ValueError('Missing public files')
    for name in ('public/index.html','public/brief/index.html','public/kabinet/index.html','public/robots.txt'):
        if name not in found: raise ValueError('Missing required page')
    return m,found
def main():
    p=argparse.ArgumentParser();p.add_argument('--commit',required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--source-ref',required=True);p.add_argument('--destination',required=True);a=p.parse_args()
    if not re.fullmatch('[a-f0-9]{40}',a.commit) or not re.fullmatch('[a-f0-9]{40}',a.source_ref) or not re.fullmatch('[a-f0-9]{64}',a.manifest_sha256): raise ValueError('Invalid pin')
    destination=Path(a.destination);prefix='public-'+a.source_ref[:7]
    if destination.parent!=BASE.parent or destination.parent.resolve()!=BASE.parent or destination.name!='20261026-'+a.source_ref[:7]+'-public' or destination.exists(): raise ValueError('Invalid new release')
    if BASE.is_symlink() or json.loads((BASE/'RELEASE.json').read_text())['sourceRef']!=BASE_REF: raise ValueError('Base runtime differs')
    raw=fetch(a.commit,prefix,'manifest.json',1024*1024)
    if digest(raw)!=a.manifest_sha256: raise ValueError('Untrusted manifest')
    m=json.loads(raw);parts=m['parts']
    if not 1<=len(parts)<=512: raise ValueError('Parts bound')
    chunks=[]
    for index,part in enumerate(parts,1):
        if part['name']!=f'p{index:04d}.bin': raise ValueError('Part sequence')
        b=fetch(a.commit,prefix,part['name'],65536)
        if len(b)!=part['bytes'] or digest(b)!=part['sha256']: raise ValueError('Part checksum')
        chunks.append(b)
    manifest,files=validate(raw,a.manifest_sha256,a.source_ref,b''.join(chunks))
    shutil.copytree(BASE,destination,symlinks=True)
    shutil.rmtree(destination/'public')
    for name,b in files.items():
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b);target.chmod(0o644)
    (destination/'PUBLIC-RELEASE.json').write_text(json.dumps({'format':1,'publicSourceRef':a.source_ref,'baseRuntimeRef':BASE_REF,'transportCommit':a.commit,'manifestSha256':a.manifest_sha256,'files':manifest['files']},indent=2)+'\n')
    print(json.dumps({'prepared':str(destination),'publicSourceRef':a.source_ref,'baseRuntimeRef':BASE_REF,'files':len(files),'serviceChanged':False}))
if __name__=='__main__': main()
