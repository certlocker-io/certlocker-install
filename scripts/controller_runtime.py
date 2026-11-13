"""Run deployment tools in a packaged Linux controller on macOS or on request."""
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {'uncloud', 'uncloudctl', 'setup-ha', 'prepare-controller'}
SCRIPT_ALIASES = {'uncloudctl': 'uncloud'}
TRANSFER_ENV = ('CERTLOCKER_TOKEN','TRUST_TOKEN','CERTLOCKER_API_URL','CERTLOCKER_ACCOUNT_ID','CERTLOCKER_API_MODE','CERTLOCKER_SMTP_PASSWORD',
    'CERTLOCKER_INITIAL_ADMIN_PASSWORD','CLOUDFLARE_API_TOKEN','CERTLOCKER_ACME_SECRET_NAME',
    'CERTLOCKER_GHCR_SECRET_NAME','CERTLOCKER_GOOGLE_CHAT_WEBHOOK_SECRET_NAME',
)


def command(args, **kwargs):
    # Bootstrap may run before RTK exists on the workstation.
    return subprocess.run(args, **kwargs)


def brew_binary():
    return shutil.which('brew') or next((str(p) for p in
        (Path('/opt/homebrew/bin/brew'),Path('/usr/local/bin/brew')) if p.exists()),None)


def install_docker():
    if platform.system()=='Darwin':
        brew=brew_binary()
        if not brew:
            print('Installing Homebrew to prepare Docker Desktop. The installer may request your macOS administrator password.',flush=True)
            url='https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh'
            with tempfile.TemporaryDirectory() as temp:
                script=Path(temp)/'brew-install.sh'
                with urllib.request.urlopen(url,timeout=30) as response:
                    script.write_bytes(response.read(1024*1024))
                command(['/bin/bash',str(script)],check=True)
            brew=brew_binary()
        if not brew:
            raise ValueError('Homebrew installation did not complete')
        command([brew,'install','--cask','docker'],check=True)
        return shutil.which('docker') or '/Applications/Docker.app/Contents/Resources/bin/docker'
    if platform.system()=='Linux' and shutil.which('apt-get'):
        sudo=[] if os.geteuid()==0 else ['sudo']
        print('Installing the Docker engine and client from Ubuntu/Debian packages.',flush=True)
        command([*sudo,'apt-get','update'],check=True)
        command([*sudo,'apt-get','install','-y','docker.io'],check=True)
        if shutil.which('systemctl'):
            command([*sudo,'systemctl','enable','--now','docker'],check=True)
        return shutil.which('docker')
    raise ValueError('Install a Docker-compatible engine for this Linux distribution, then rerun ./prepare-controller')


def docker_command():
    binary=shutil.which('docker')
    bundled=Path('/Applications/Docker.app/Contents/Resources/bin/docker')
    if not binary and platform.system()=='Darwin' and bundled.is_file():
        binary=str(bundled)
    if not binary:
        binary=install_docker()
    os.environ['PATH']=str(Path(binary).resolve().parent)+os.pathsep+os.environ.get('PATH','')
    def ready(prefix):
        try:
            return command([*prefix,'info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode==0
        except subprocess.TimeoutExpired:
            return False
    prefix=[binary]
    if ready(prefix):
        return prefix
    if platform.system()=='Darwin':
        print('Starting Docker Desktop. Complete any macOS first-run prompts in its window.',flush=True)
        command(['open','-a','Docker'],check=True)
        started=time.monotonic()
        while time.monotonic()-started<180:
            if ready(prefix):
                return prefix
            print('Waiting for Docker Desktop to be ready…',flush=True)
            time.sleep(5)
        raise ValueError('Docker Desktop is not ready. Finish its setup, then rerun this command')
    if shutil.which('sudo'):
        # Preserve only the explicitly supported in-memory credential variables.
        prefix=['sudo','--preserve-env='+','.join(TRANSFER_ENV),binary]
        if ready(prefix):
            return prefix
    raise ValueError('Docker is installed but its engine is unavailable. Start the engine and retry')


def image_tag(uid, gid):
    digest=hashlib.sha256()
    for file in sorted((ROOT/'controller').iterdir()):
        if file.is_file():
            digest.update(file.name.encode());digest.update(file.read_bytes())
    digest.update(f'{uid}:{gid}'.encode())
    return 'certlocker-deployment-controller:'+digest.hexdigest()[:16]


def ensure_image(docker):
    uid,gid=os.getuid(),os.getgid()
    tag=image_tag(uid,gid)
    found=command([*docker,'image','inspect',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if found.returncode:
        print('Build the controller with all required deployment packages. No credentials enter the build context.',flush=True)
        command([*docker,'build','--build-arg',f'CONTROLLER_UID={uid}',
            '--build-arg',f'CONTROLLER_GID={gid}','-t',tag,str(ROOT/'controller')],check=True)
    return tag


def workstation_google_login(arguments):
    loader=importlib.machinery.SourceFileLoader('workstation_google',str(ROOT/'scripts/prepare-ha-workstation'))
    spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    os.environ.setdefault('CLOUDSDK_PYTHON',sys.executable)
    installed=Path.home()/'.local/share/certlocker/tools'/('google-cloud-sdk-'+module.VERSION)
    binary=shutil.which('gcloud')
    if not binary:
        binary=installed/'bin/gcloud' if (installed/'bin/gcloud').exists() else module.install_gcloud(installed)
    interactive=sys.stdin.isatty() and '--non-interactive' not in arguments
    active=command([str(binary),'auth','print-access-token','--quiet'],capture_output=True,text=True)
    if (arguments and arguments[0]=='up' and interactive) or active.returncode:
        if not interactive:
            raise ValueError('Google login is required. Run '+str(binary)+' auth login --update-adc on your workstation')
        environment=dict(os.environ);environment.pop('CLOUDSDK_CORE_DISABLE_PROMPTS',None)
        command([str(binary),'auth','login','--update-adc'],env=environment,check=True)
    return Path(os.environ.get('CLOUDSDK_CONFIG',str(Path.home()/'.config/gcloud'))).expanduser().resolve()


def container_arguments(operation, arguments, image, gcloud_config=None):
    home=Path.home();controller_home=home/'.local/share/certlocker/controller-home'
    for path in (controller_home,home/'.ssh'):
        path.mkdir(parents=True,exist_ok=True,mode=0o700)
    docker_args=['run','--rm','--init','--memory=2g','--memory-swap=2g','--shm-size=256m',
        '--tmpfs','/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777','--workdir','/workspace',
        '--mount',f'type=bind,source={ROOT},target=/workspace',
        '--mount',f'type=bind,source={controller_home},target=/home/controller',
        '--mount',f'type=bind,source={home/".ssh"},target=/home/controller/.ssh']
    if sys.stdin.isatty() and sys.stdout.isatty():
        docker_args+=['-it']
    else:
        docker_args+=['-i']
    for variable in TRANSFER_ENV:
        if variable in os.environ:
            docker_args+=['--env',variable]
    if gcloud_config is not None:
        gcloud_config.mkdir(parents=True,exist_ok=True,mode=0o700)
        docker_args+=['--mount',f'type=bind,source={gcloud_config},target=/home/controller/.config/gcloud',
                      '--env','CERTLOCKER_GOOGLE_LOGIN_DONE=1']
    translated=[]
    path_flags={'--ssh-key','--master-key-file','--manifest-file','--config','--state-dir'}
    index=0
    while index<len(arguments):
        arg=arguments[index];flag,separator,value=arg.partition('=')
        if flag in path_flags:
            if not separator:
                index+=1
                if index>=len(arguments):
                    raise ValueError(flag+' requires a path')
                value=arguments[index]
            source=Path(value).expanduser().resolve()
            if source.is_relative_to(ROOT):
                target='/workspace/'+str(source.relative_to(ROOT))
            elif source.is_relative_to(home/'.ssh'):
                target='/home/controller/.ssh/'+str(source.relative_to(home/'.ssh'))
            else:
                if flag=='--state-dir':
                    source.mkdir(parents=True,exist_ok=True,mode=0o700)
                if not source.exists():
                    raise ValueError('Input path does not exist: '+str(source))
                target='/inputs/'+str(len(translated))+'/'+source.name
                mount=f'type=bind,source={source},target={target}'
                if flag!='--state-dir':mount+=',readonly'
                docker_args+=['--mount',mount]
                if flag=='--manifest-file':
                    checksum=source.with_suffix(source.suffix+'.sha256')
                    if not checksum.is_file():
                        raise ValueError('Release manifest checksum is required')
                    docker_args+=['--mount',f'type=bind,source={checksum},target={target}.sha256,readonly']
            translated+=[flag,target]
        else:
            translated.append(arg)
        index+=1
    return [*docker_args,image,'scripts/'+operation,*translated]


def main(argv=None):
    values=list(sys.argv[1:] if argv is None else argv)
    if not values or values[0] not in OPERATIONS:
        raise ValueError('Choose a supported deployment command')
    operation,*arguments=values
    script=SCRIPT_ALIASES.get(operation, operation)
    native_tools=('terraform','gcloud','ansible-playbook','ansible-galaxy','uc','ssh','ssh-keygen','openssl')
    native_ready=all(shutil.which(tool) for tool in native_tools) and all(
        importlib.util.find_spec(module) is not None for module in ('yaml','cryptography','argon2'))
    use_container=(platform.system()=='Darwin' or not native_ready or
                   os.environ.get('CERTLOCKER_USE_CONTROLLER')=='1' or operation=='prepare-controller')
    if not use_container or '--help' in arguments or '-h' in arguments:
        if operation!='prepare-controller':
            os.execv(sys.executable,[sys.executable,str(ROOT/'scripts'/script),*arguments])
    docker=docker_command();image=ensure_image(docker)
    if operation=='prepare-controller':
        smoke=container_arguments('uncloud',[],image)
        smoke[-1:]=['-c',"import sys;sys.path.insert(0,'scripts');from uncloud_preflight import check_controller;check_controller(require_google=True,require_terraform=True)"]
        command([*docker,*smoke],check=True)
        print('Deployment controller is ready for macOS or Linux.',flush=True)
        return
    gcloud_config=workstation_google_login(arguments) if script in ('uncloud', 'setup-ha') else None
    command([*docker,*container_arguments(script,arguments,image,gcloud_config)],check=True)

if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        raise SystemExit('Controller preparation stopped: '+str(error)) from None
