"""Run on an enrolled bare-metal node over a pinned SSH connection."""
import os
import pwd
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys


def output(*cmd):
    return subprocess.check_output(cmd, text=True).splitlines()


def run(*cmd):
    subprocess.run(cmd, check=True)


def remove(path):
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def main(action, company, node, machine, hostname):
    marker = Path('/etc/certlocker-uncloud')
    if (not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', company) or node not in (company+'-a', company+'-b')
            or Path('/etc/machine-id').read_text().strip() != machine or socket.gethostname().split('.')[0] != hostname):
        raise ValueError('Server identity mismatch')
    if marker.exists() and marker.read_text().strip() != node:
        raise ValueError('Server enrollment mismatch')
    projects = ['certlocker-' + company + '-' + p for p in ('ingress','monitoring','apps','router-proxy')]
    projects.append('certlocker-uncloud-db')
    units = ['certlocker-' + company + '-' + s for s in ('ha.timer','ha.service','api-owner.service','runtime.service')]
    units += ['certlocker-uncloud-db.service','certlocker-uncloud-local-route.service',
              'certlocker-docker-prune.timer','certlocker-docker-prune.service']
    def resources(kind, project):
        cmd = ['docker', kind, 'ls', '-q']
        if kind == 'container':
            cmd.append('-a')
        return output(*cmd, '--filter', 'label=com.docker.compose.project=' + project)
    if not marker.exists() or action == 'verify':
        if (marker.exists() or Path('/var/lib/uncloud').exists() or Path('/opt/certlocker', company).exists()
                or any(resources(kind, p) for p in projects for kind in ('container','volume','network'))):
            raise ValueError('Uninstall incomplete or ownership marker missing on ' + hostname)
        print(hostname, 'verified clean')
        return
    if action == 'check':
        print(hostname, 'verified enrollment', node)
        return
    if action != 'remove':
        raise ValueError('Invalid operation')
    remove(f'/etc/systemd/system/docker.service.d/certlocker-{company}-runtime.conf')
    run('systemctl', 'daemon-reload')
    for unit in units:
        if Path('/etc/systemd/system', unit).exists():
            run('systemctl','stop',unit)
            run('systemctl','disable',unit)
    for p in projects:
        for kind, flags in [('container',['-f','-v']),('volume',[]),('network',[])]:
            ids = resources(kind, p)
            if ids:
                run('docker', kind, 'rm', *flags, *ids)
    for rule in output('iptables','-t','nat','-S','POSTROUTING'):
        words = shlex.split(rule)
        if 'CertLocker local mesh identity' in words:
            run('iptables','-w','10','-t','nat','-D',*words[1:])
    uninstaller = Path('/usr/local/bin/uncloud-uninstall')
    if uninstaller.exists():
        subprocess.run([uninstaller], env=dict(os.environ, AUTO_CONFIRM='true'), check=True)
    if Path('/var/lib/uncloud').exists() or output('docker','network','ls','--filter','name=^uncloud$','-q'):
        raise ValueError('Mesh removal incomplete')
    for line in output('ufw','show','added'):
        rule = shlex.split(line)
        if rule[:2] == ['ufw','allow'] and 'comment' in rule and rule[-1] in (
                'Uncloud peer tunnel','Uncloud authenticated private overlay','CertLocker HAProxy origin'):
            run('ufw','--force','delete', *rule[1:rule.index('comment')])
    for unit in units:
        remove(Path('/etc/systemd/system', unit))
    public = Path('/etc/certlocker', company, 'certificate-deploy.pub')
    try:
        authorized = Path(pwd.getpwnam('cl-cert-deploy').pw_dir) / '.ssh/authorized_keys'
    except KeyError:
        authorized = None
    if public.is_file() and authorized and authorized.is_file():
        parts = public.read_text().split()
        if len(parts) < 2 or parts[0] != 'ssh-rsa':
            raise ValueError('Malformed installation certificate deployment public key')
        lines = authorized.read_text().splitlines(keepends=True)
        authorized.write_text(''.join(line for line in lines if line.split()[1:3] != parts[:2]))
    for name in ('certificate-activate', 'uncloud-api-owner', 'uncloud-db-start', 'uncloud-docker-prune',
                 'uncloud-local-route', 'uncloud-router-proxy', 'uncloud-runtime', 'uncloud-watchdog', 'uncloud-release'):
        remove(Path('/usr/local/sbin', 'certlocker-' + name))
    for name in ('uncloud_certificate_bundle.py', 'uncloud_gcp.py'):
        remove(Path('/usr/local/sbin', name))
    for base in ('/opt/certlocker','/etc/certlocker','/run/certlocker','/var/lib/certlocker',
                 '/run/certlocker-certificate-inbox'):
        remove(Path(base, company))
    for path in ('/opt/certlocker/uncloud-db','/var/lib/certlocker-uncloud/identity.sha256',
                 f'/etc/systemd/system/docker.service.d/certlocker-{company}-runtime.conf',
                 f'/etc/tmpfiles.d/certlocker-{company}-certificate.conf', f'/etc/tmpfiles.d/certlocker-{company}-ansible.conf',
                 f'/etc/sudoers.d/certlocker-{company}-certificate', f'/run/certlocker-{company}-ansible',
                 f'/run/certlocker-{company}-api-owner.lock', f'/run/certlocker-{company}-ha.lock'):
        remove(path)
    run('systemctl','daemon-reload')
    marker.unlink()
    print(hostname, 'stack removed')


if __name__ == '__main__':
    main(*sys.argv[1:])
