#!/usr/bin/env python3
"""Prepare a new inactive release from verified private staging.

Does not run npm, activate the service, touch current/runtime.env, or change DNS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import grp
import shutil
import stat

from receive_runtime import path_name


def verify_directory(source, expected_source):
    source = Path(source)
    if source.is_symlink() or source.resolve() != source or not source.is_dir():
        raise ValueError('Expected canonical release directory')
    release = json.loads((source / 'RELEASE.json').read_bytes())
    if release.get('sourceRef') != expected_source or release.get('mode') != 'russian-node-runtime' or release.get('format') != 1 or release.get('api') != 'disabled' or release.get('dnsCutoverReady') is not False:
        raise ValueError('Unexpected source release')
    names = set()
    for entry in release['files']:
        name = path_name(entry['path'])
        if name in names or name == 'RELEASE.json':
            raise ValueError('Duplicate manifest file')
        names.add(name)
        file = source.joinpath(*name.split('/'))
        if not file.is_file() or file.is_symlink():
            raise ValueError('Release regular file missing')
        value = file.read_bytes()
        if len(value) != entry['bytes'] or hashlib.sha256(value).hexdigest() != entry['sha256']:
            raise ValueError('Release file hash mismatch')
    actual = set()
    for root, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            file = Path(root) / name
            if file.is_symlink():
                raise ValueError('Release contains a symlink')
            if file.is_file():
                actual.add(file.relative_to(source).as_posix())
            elif not file.is_dir():
                raise ValueError('Release contains a special file')
    if actual != names | {'RELEASE.json'}:
        raise ValueError('Release contains unexpected files')
    return release


def prepare(source, destination, expected_source, runtime_group='averkron'):
    source, destination = Path(source), Path(destination)
    release = verify_directory(source, expected_source)
    if not destination.is_absolute() or destination.parent.resolve() != destination.parent or destination.exists() or destination.is_symlink():
        raise ValueError('Use a new canonical inactive release destination')
    if destination.parent != Path('/srv/averkron/releases'):
        raise ValueError('Release destination must be directly under /srv/averkron/releases')
    if os.geteuid() != 0:
        raise ValueError('Release preparation requires the server administrator')
    group_id = grp.getgrnam(runtime_group).gr_gid
    copied = False
    try:
        shutil.copytree(source, destination, symlinks=False)
        copied = True
        verify_directory(destination, expected_source)
        for root, directories, files in os.walk(destination):
            for file in [Path(root)] + [Path(root) / name for name in directories + files]:
                info = file.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError('Unexpected installed entry')
                os.chown(file, 0, group_id, follow_symlinks=False)
                os.chmod(file, 0o750 if file.is_dir() else 0o640, follow_symlinks=False)
        return {'prepared': str(destination), 'sourceRef': expected_source, 'files': len(release['files']),
            'dependenciesInstalled': False, 'serviceChanged': False, 'apiEnabled': False, 'dnsChanged': False}
    except Exception:
        if copied:
            shutil.rmtree(destination)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--source-ref', required=True)
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.source, arguments.destination, arguments.source_ref), sort_keys=True))
