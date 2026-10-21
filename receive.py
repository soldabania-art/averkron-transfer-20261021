#!/usr/bin/env python3
"""Receive authenticated ciphertext; key stays on the receiving terminal."""
import getpass, hashlib, json, os, pathlib, sys, tarfile, time, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def digest(data):
    return hashlib.sha256(data).hexdigest()

def fetch(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                return response.read()
        except Exception:
            if attempt == 2:
                raise
            time.sleep(1)

def extract(archive, target):
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle.getmembers():
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe archive entry')
        bundle.extractall(target, filter='data')

def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    os.umask(0o077)
    base = sys.argv[1].rstrip('/')
    manifest = json.loads(fetch(base + '/manifest.json'))
    root = pathlib.Path('/root/averkron-transfer-20261021')
    root.mkdir(mode=0o700, exist_ok=True)
    payload = bytearray()
    for item in manifest['parts']:
        part = root / item['file']
        data = part.read_bytes() if part.exists() else b''
        if digest(data) != item['sha256']:
            data = fetch(base + '/' + item['file'])
            if len(data) != item['bytes'] or digest(data) != item['sha256']:
                raise ValueError('Part checksum failed: ' + item['file'])
            part.write_bytes(data)
        payload.extend(data)
        print('Verified ' + item['file'], flush=True)
    if digest(payload) != manifest['ciphertextSha256']:
        raise ValueError('Ciphertext checksum failed')
    key = bytes.fromhex(getpass.getpass('Transfer key (hidden): '))
    plaintext = AESGCM(key).decrypt(bytes(payload[:12]), bytes(payload[12:]), None)
    if digest(plaintext) != manifest['archiveSha256']:
        raise ValueError('Archive checksum failed')
    archive = root / 'transfer.tar.gz'
    archive.write_bytes(plaintext)
    extract(archive, root / 'unpacked')
    print('TRANSFER_OK sha256=' + digest(plaintext), flush=True)
    print('Private files: ' + str(root / 'unpacked'), flush=True)
    print('No services or DNS changed.', flush=True)

if __name__ == '__main__':
    main()
