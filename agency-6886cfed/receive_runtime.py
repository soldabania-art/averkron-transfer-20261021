#!/usr/bin/env python3
"""Verify/decrypt a pinned ciphertext transport and stage sources privately.

Uses Python stdlib, OpenSSL RSA-OAEP and the installed Node 24 AES-GCM crypto. It never enables
APIs, edits runtime.env, changes a service/current symlink, or changes DNS/MX.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.parse
import urllib.request

FORMAT = 'averkron-encrypted-runtime-v1'
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 10000
REPOSITORY = 'soldabania-art/averkron-transfer-20261021'
HASH = re.compile('[a-f0-9]{64}')
NODE_DECRYPT = r"""
const fs=require('fs'),crypto=require('crypto');
try{
 const [manifestPath,cipherPath]=process.argv.slice(1);
 const m=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
 const key=fs.readFileSync(0);
 if(key.length!==32)throw Error('key');
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(m.encryption.nonce,'base64'));
 decipher.setAAD(Buffer.from(m.encryption.aad,'base64'));
 decipher.setAuthTag(Buffer.from(m.encryption.tag,'base64'));
 const plaintext=Buffer.concat([decipher.update(fs.readFileSync(cipherPath)),decipher.final()]);
 key.fill(0);
 fs.writeSync(1,plaintext);
}catch{process.stderr.write('Runtime decryption failed\n');process.exitCode=1;}
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unbase64(value, length=None):
    if not isinstance(value, str):
        raise ValueError('Invalid encoded envelope')
    data = base64.b64decode(value, validate=True)
    if base64.b64encode(data).decode('ascii') != value or length is not None and len(data) != length:
        raise ValueError('Invalid encoded envelope')
    return data


def regular_private(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o600:
        raise ValueError('Expected an owned private regular file')


def private_parent(path):
    if not path.is_absolute() or str(path.parent.resolve()) != str(path.parent):
        raise ValueError('Expected an absolute canonical staging path')
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
        raise ValueError('Staging parent must be owned and mode 0700')
    for forbidden in ['/var/www', '/www', '/usr/share/nginx', '/srv/averkron/current']:
        base = Path(forbidden)
        if path == base or base in path.parents:
            raise ValueError('Staging must stay outside public/server document roots')


def path_name(value):
    if not isinstance(value, str) or not value or len(value) > 512 or '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid archive path')
    while value.startswith('./'):
        value = value[2:]
    value = value.rstrip('/')
    if not value or value.startswith('/') or any(part in ['', '.', '..'] for part in value.split('/')):
        raise ValueError('Unsafe archive path')
    return value


def manifest_data(raw, expected_hash, source_ref):
    if len(raw) > 256 * 1024 or sha(raw) != expected_hash:
        raise ValueError('Pinned transport manifest hash mismatch')
    data = json.loads(raw)
    if data.get('format') != FORMAT or data.get('sourceRef') != source_ref:
        raise ValueError('Unexpected transport/source')
    archive, encryption, ciphertext = data['archive'], data['encryption'], data['ciphertext']
    if not isinstance(archive.get('bytes'), int) or not 1 <= archive['bytes'] <= MAX_ARCHIVE or not HASH.fullmatch(archive.get('sha256', '')) or not HASH.fullmatch(archive.get('releaseSha256', '')):
        raise ValueError('Invalid archive identity')
    if encryption.get('algorithm') != 'AES-256-GCM' or encryption.get('wrapping') != 'RSA-OAEP-SHA256' or not HASH.fullmatch(encryption.get('publicKeySha256', '')):
        raise ValueError('Unsupported encryption envelope')
    unbase64(encryption['nonce'], 12)
    unbase64(encryption['tag'], 16)
    if not 256 <= len(unbase64(encryption['wrappedKey'])) <= 1024:
        raise ValueError('Invalid wrapped key length')
    expected_aad = ('averkron-agency-runtime\0v1\0' + source_ref + '\0' + archive['sha256'] + '\0' + encryption['publicKeySha256']).encode('ascii')
    if unbase64(encryption['aad']) != expected_aad:
        raise ValueError('Envelope identity mismatch')
    parts = ciphertext.get('parts')
    if ciphertext.get('bytes') != archive['bytes'] or not HASH.fullmatch(ciphertext.get('sha256', '')) or not isinstance(parts, list) or not 1 <= len(parts) <= 8192:
        raise ValueError('Invalid ciphertext manifest')
    for index, part in enumerate(parts, 1):
        if part.get('name') != 'p%04d.bin' % index or not isinstance(part.get('bytes'), int) or not 1 <= part['bytes'] <= 1024 * 1024 or not HASH.fullmatch(part.get('sha256', '')):
            raise ValueError('Invalid ciphertext part')
    if sum(part['bytes'] for part in parts) != ciphertext['bytes']:
        raise ValueError('Ciphertext length mismatch')
    return data


def fetch(url, length, digest):
    with urllib.request.urlopen(url, timeout=30) as response:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https' or final.hostname != 'raw.githubusercontent.com':
            raise ValueError('Unexpected download destination')
        value = response.read(length + 1)
    if len(value) != length or sha(value) != digest:
        raise ValueError('Transport download hash/length mismatch')
    return value


def verified_release(package, source_ref, release_hash):
    entries, directories, seen = {}, set(), set()
    expanded = 0
    for count, member in enumerate(package, 1):
        if count > MAX_FILES * 2:
            raise ValueError('Too many archive entries')
        if member.name in ['.', './'] and member.isdir():
            continue
        name = path_name(member.name)
        if name in seen or not (member.isdir() or member.isfile()) or member.sparse is not None:
            raise ValueError('Duplicate/linked/special/sparse archive entry')
        seen.add(name)
        if member.isdir():
            directories.add(name)
        else:
            if member.size < 0 or member.size > 32 * 1024 * 1024:
                raise ValueError('Oversized archive member')
            expanded += member.size
            if expanded > MAX_TOTAL + 2 * 1024 * 1024:
                raise ValueError('Archive expansion limit exceeded')
            entries[name] = member
    if 'RELEASE.json' not in entries or entries['RELEASE.json'].size > 2 * 1024 * 1024:
        raise ValueError('Missing release manifest')
    release_bytes = package.extractfile(entries['RELEASE.json']).read()
    if sha(release_bytes) != release_hash:
        raise ValueError('RELEASE.json hash mismatch')
    release = json.loads(release_bytes)
    if release.get('format') != 1 or release.get('sourceRef') != source_ref or release.get('mode') != 'russian-node-runtime' or release.get('entry') != 'server/russian-main.cjs' or release.get('api') != 'disabled' or release.get('dnsCutoverReady') is not False:
        raise ValueError('Unexpected release contract')
    expected = {}
    if not isinstance(release.get('files'), list) or not 1 <= len(release['files']) <= MAX_FILES:
        raise ValueError('Invalid release inventory')
    for item in release['files']:
        name = path_name(item.get('path'))
        if name == 'RELEASE.json' or name in expected or not isinstance(item.get('bytes'), int) or not 0 <= item['bytes'] <= 32 * 1024 * 1024 or not HASH.fullmatch(item.get('sha256', '')):
            raise ValueError('Invalid release inventory row')
        expected[name] = item
    if set(entries) != set(expected) | {'RELEASE.json'} or sum(item['bytes'] for item in expected.values()) > MAX_TOTAL:
        raise ValueError('Unexpected archive files or expansion limit')
    for name in directories:
        if not any(file.startswith(name + '/') for file in entries):
            raise ValueError('Unexpected empty archive directory')
    for name, item in expected.items():
        if entries[name].size != item['bytes']:
            raise ValueError('Archive inventory size mismatch')
    for required in ['public/index.html', 'public/404.html', 'public/robots.txt', 'public/sitemap.xml', 'public/kabinet/index.html', 'server/russian-main.cjs', 'server/russian-runtime.cjs', 'server/http.cjs', 'package.json', 'package-lock.json']:
        if required not in expected:
            raise ValueError('Incomplete runtime release')
    return entries, expected


def extract_verified(archive, output, source_ref, release_hash):
    output = Path(output)
    private_parent(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Staging destination already exists')
    created = False
    try:
        with tarfile.open(archive, 'r:gz') as package:
            entries, expected = verified_release(package, source_ref, release_hash)
            output.mkdir(mode=0o700)
            created = True
            for name, member in entries.items():
                target = output.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                received = 0
                checksum = hashlib.sha256()
                with package.extractfile(member) as source, os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as destination:
                    while True:
                        value = source.read(65536)
                        if not value:
                            break
                        received += len(value)
                        if received > member.size:
                            raise ValueError('Expanded file exceeds declared length')
                        checksum.update(value)
                        destination.write(value)
                    destination.flush()
                    os.fsync(destination.fileno())
                item = expected.get(name)
                if received != member.size or item and checksum.hexdigest() != item['sha256']:
                    raise ValueError('Extracted release content hash mismatch')
            for directory, _, _ in os.walk(output, topdown=False):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        return len(expected)
    except Exception:
        if created:
            shutil.rmtree(output)
        raise


def receive(commit, prefix, manifest_hash, source_ref, private_key, output, node):
    if not re.fullmatch('[a-f0-9]{40}', commit) or not re.fullmatch('[a-f0-9]{40}', source_ref) or not HASH.fullmatch(manifest_hash):
        raise ValueError('Pinned commit, source SHA and manifest SHA256 are required')
    if not re.fullmatch('[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', prefix):
        raise ValueError('Invalid transport prefix')
    private_key, output = Path(private_key), Path(output)
    regular_private(private_key)
    private_parent(output)
    work = output.parent / ('incoming-' + manifest_hash[:16])
    work.mkdir(mode=0o700, exist_ok=True)
    info = work.lstat()
    if not stat.S_ISDIR(info.st_mode) or work.resolve() != work or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
        raise ValueError('Invalid private download workspace')
    for entry in work.iterdir():
        if entry.name not in ['manifest.json', 'payload.enc', 'runtime.tar.gz']:
            raise ValueError('Unexpected private workspace file')
        regular_private(entry)
    origin = 'https://raw.githubusercontent.com/' + REPOSITORY + '/' + commit + '/' + prefix + '/'
    with urllib.request.urlopen(origin + 'manifest.json', timeout=30) as response:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https' or final.hostname != 'raw.githubusercontent.com':
            raise ValueError('Unexpected manifest download destination')
        raw = response.read(256 * 1024 + 1)
    data = manifest_data(raw, manifest_hash, source_ref)
    public = subprocess.run(['openssl', 'pkey', '-in', str(private_key), '-pubout', '-outform', 'DER'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if public.returncode != 0 or sha(public.stdout) != data['encryption']['publicKeySha256']:
        raise ValueError('Server private key/public fingerprint mismatch')
    manifest_file = work / 'manifest.json'
    if manifest_file.exists():
        if sha(manifest_file.read_bytes()) != manifest_hash:
            raise ValueError('Existing transport manifest differs')
    else:
        with os.fdopen(os.open(manifest_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as handle:
            handle.write(raw)
    cipher_file = work / 'payload.enc'
    valid_cipher = cipher_file.exists() and cipher_file.stat().st_size == data['ciphertext']['bytes'] and sha(cipher_file.read_bytes()) == data['ciphertext']['sha256']
    if not valid_cipher:
        if cipher_file.exists():
            cipher_file.unlink()
        checksum = hashlib.sha256()
        with open(cipher_file, 'xb') as combined:
            os.chmod(combined.fileno(), 0o600)
            for part in data['ciphertext']['parts']:
                value = fetch(origin + part['name'], part['bytes'], part['sha256'])
                checksum.update(value)
                combined.write(value)
            combined.flush()
            os.fsync(combined.fileno())
        if checksum.hexdigest() != data['ciphertext']['sha256']:
            raise ValueError('Combined ciphertext hash mismatch')
    archive = work / 'runtime.tar.gz'
    valid_archive = archive.exists() and archive.stat().st_size == data['archive']['bytes'] and sha(archive.read_bytes()) == data['archive']['sha256']
    if not valid_archive:
        if archive.exists():
            archive.unlink()
        with open(archive, 'xb') as destination:
            os.chmod(destination.fileno(), 0o600)
            wrapped = unbase64(data['encryption']['wrappedKey'])
            unwrapped = subprocess.run(['openssl', 'pkeyutl', '-decrypt', '-inkey', str(private_key),
                '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'],
                input=wrapped, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if unwrapped.returncode != 0 or len(unwrapped.stdout) != 32:
                raise ValueError('Server key unwrap failed')
            # The unwrapped AES key goes only through a local child stdin pipe;
            # it is never written to a file, argv, log, or parent stdout.
            result = subprocess.run([node, '-e', NODE_DECRYPT, str(manifest_file), str(cipher_file)], input=unwrapped.stdout,
                stdout=destination, stderr=subprocess.PIPE, timeout=60)
            del unwrapped
            destination.flush()
            os.fsync(destination.fileno())
        if result.returncode != 0:
            raise ValueError('Runtime decryption failed')
    if archive.stat().st_size != data['archive']['bytes'] or sha(archive.read_bytes()) != data['archive']['sha256']:
        raise ValueError('Decrypted archive identity mismatch')
    files = extract_verified(archive, output, source_ref, data['archive']['releaseSha256'])
    return {'verified': True, 'sourceRef': source_ref, 'archiveSha256': data['archive']['sha256'], 'files': files,
        'staging': str(output), 'apiEnabled': False, 'serviceChanged': False, 'dnsChanged': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-ref', required=True)
    parser.add_argument('--private-key', default='/root/ak26/k.pem')
    parser.add_argument('--output', required=True)
    parser.add_argument('--node', default='/opt/node-v24.22.0-linux-x64/bin/node')
    args = parser.parse_args()
    print(json.dumps(receive(args.commit, args.prefix, args.manifest_sha256, args.source_ref, args.private_key, args.output, args.node), sort_keys=True))
