#!/usr/bin/env python3
"""Build release archives with the local Go toolchain; no publishing side effects."""
import argparse
import concurrent.futures
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    date = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    out = ROOT / 'dist' / args.version
    out.mkdir(parents=True, exist_ok=True)
    docs = ['LICENSE', 'README.md', 'MIGRATION.md', 'CHANGELOG.md']

    def build(platform):
        goos, arch = platform
        folder = out / f'{goos}_{arch}'
        folder.mkdir(exist_ok=True)
        binary = folder / ('sift.exe' if goos == 'windows' else 'sift')
        env = dict(os.environ, GOOS=goos, GOARCH=arch, CGO_ENABLED='0')
        subprocess.run(['go', 'build', '-trimpath', '-ldflags',
                        f'-s -w -X main.version={args.version} -X main.commit={commit} -X main.date={date}',
                        '-o', str(binary), './cmd/sift'], cwd=ROOT, env=env, check=True)
        name = f'sift_{goos}_{arch}'
        if goos == 'windows':
            archive = out / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
                package.write(binary, binary.name)
                for doc in docs:
                    package.write(ROOT / doc, doc)
        else:
            archive = out / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as package:
                package.add(binary, arcname=binary.name)
                for doc in docs:
                    package.add(ROOT / doc, arcname=doc)
        print(archive.name, flush=True)
        return archive

    platforms = [(system, arch) for system in ['linux', 'darwin', 'windows'] for arch in ['amd64', 'arm64']]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        archives = list(pool.map(build, platforms))
    (out / 'checksums.txt').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in sorted(archives)))
    print(f'Built {len(archives)} archives at {commit}', flush=True)


if __name__ == '__main__':
    main()
