"""Install checksum-pinned public tools during the controller image build."""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def install():
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if arch is None:
        raise SystemExit('Controller images support amd64 and arm64')
    tools=json.loads(Path('/bootstrap/tools.lock.json').read_text())
    for name,tool in tools.items():
        url=tool['url'].format(arch=arch,target=tool.get('targets',{}).get(arch,''))
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);archive=directory/'archive'
            digest=hashlib.sha256();total=0
            with urllib.request.urlopen(url,timeout=120) as response,archive.open('wb') as stream:
                while chunk:=response.read(1024*1024):
                    total+=len(chunk)
                    if total>300*1024*1024:
                        raise SystemExit('Tool archive exceeds download size bound')
                    digest.update(chunk);stream.write(chunk)
            if digest.hexdigest()!=tool['hashes'][arch]:
                raise SystemExit('Checksum mismatch for '+name)
            unpack=directory/'unpack';unpack.mkdir()
            if url.endswith('.zip'):
                with zipfile.ZipFile(archive) as source:
                    if any(Path(row.filename).is_absolute() or '..' in Path(row.filename).parts for row in source.infolist()):
                        raise SystemExit('Unsafe zip path')
                    source.extractall(unpack)
            else:
                with tarfile.open(archive) as source:
                    source.extractall(unpack,filter='data')
            if name=='gcloud':
                target=Path('/opt/google-cloud-sdk')
                shutil.move(str(unpack/'google-cloud-sdk'),target)
                subprocess.run([str(target/'install.sh'),'--quiet','--usage-reporting=false',
                    '--path-update=false','--command-completion=false','--install-python=false'],check=True,
                    env={**os.environ,'CLOUDSDK_CONFIG':str(directory/'config')})
                Path('/usr/local/bin/gcloud').symlink_to(target/'bin/gcloud')
            else:
                found=[file for file in unpack.rglob(name) if file.is_file()]
                if len(found)!=1:
                    raise SystemExit('Ambiguous binary in '+name+' archive')
                destination=Path('/usr/local/bin')/name
                shutil.copy2(found[0],destination);destination.chmod(0o755)
            print('Installed '+name+' '+tool['version'],flush=True)

if __name__=='__main__':
    install()
