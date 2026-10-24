"""Install the free engine bundle from pinned, hash-verified upstream releases."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tempfile
import urllib.request
import zipfile
from importlib.resources import files

_DEFAULT_HOME = Path.home() / '.atlas' / 'engines'


def platform_key():
    system = {'Linux': 'linux', 'Windows': 'windows'}.get(platform.system())
    machine = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64',
               'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine())
    return f'{system}_{machine}'


def manifest():
    return json.loads(files('atlas_data').joinpath('engines.lock.json').read_text(encoding='utf-8'))


def home():
    return Path(os.environ.get('ATLAS_ENGINE_HOME', str(_DEFAULT_HOME))).expanduser().resolve()


def activate():
    """Use ATLAS's managed tools without changing the user's persistent PATH."""
    directory = str(home() / platform_key() / 'bin')
    entries = os.environ.get('PATH', '').split(os.pathsep)
    if directory not in entries:
        os.environ['PATH'] = os.pathsep.join([directory] + entries)


def unpack(data, name, expected_hash, windows=False):
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError('Archive SHA-256 mismatch for ' + name)
    filename = name + ('.exe' if windows else '')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        candidates = [entry for entry in archive.infolist()
                      if Path(entry.filename).name == filename and not entry.is_dir()]
        if len(candidates) != 1 or candidates[0].file_size > 200 * 1024 * 1024:
            raise ValueError('Unexpected executable archive for ' + name)
        binary = archive.read(candidates[0])
        notices = {entry.filename: archive.read(entry).decode('utf-8', errors='replace')
                   for entry in archive.infolist()
                   if Path(entry.filename).name.upper().startswith(('LICENSE', 'NOTICE'))
                   and entry.file_size < 1024 * 1024 and not entry.is_dir()}
    return binary, notices


def install(names=None, list_only=False):
    key = platform_key()
    available = manifest().get(key)
    if not available:
        print('Bundle supports Linux x86_64/arm64 and Windows x86_64. Use WSL on other Windows systems.')
        return 2
    selected = list(available) if not names else names
    if any(name not in available for name in selected):
        print('Unknown bundle engine. Available: ' + ', '.join(available))
        return 2
    destination = home() / key / 'bin'
    failed = []
    for name in selected:
        record = available[name]
        print(f'{name}: {record["version"]} | free/open source | {record["license"]}', flush=True)
        if list_only:
            continue
        try:
            target = destination / (name + ('.exe' if key.startswith('windows') else ''))
            metadata = target.with_suffix('.atlas.json')
            if target.is_file() and metadata.is_file():
                try:
                    saved = json.loads(metadata.read_text(encoding='utf-8'))
                    if not isinstance(saved, dict):
                        saved = {}
                except (ValueError, UnicodeError):
                    saved = {}
                if (saved.get('archive_sha256') == record['sha256'] and
                        saved.get('binary_sha256') == hashlib.sha256(target.read_bytes()).hexdigest()):
                    if record.get('license_resource'):
                        saved.update(record)
                        saved.setdefault('notices', {})['LICENSE'] = files('atlas_data').joinpath(record['license_resource']).read_text(encoding='utf-8')
                        metadata.write_text(json.dumps(saved, indent=2), encoding='utf-8')
                    print('  verified existing installation', flush=True)
                    continue
            request = urllib.request.Request(record['url'], headers={'User-Agent': 'ATLAS-free-engine-installer'})
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read(record['size'] + 1)
            if len(data) != record['size']:
                raise ValueError('Archive size mismatch')
            binary, notices = unpack(data, name, record['sha256'], key.startswith('windows'))
            if record.get('license_resource'):
                notices['LICENSE'] = files('atlas_data').joinpath(record['license_resource']).read_text(encoding='utf-8')
            destination.mkdir(parents=True, exist_ok=True)
            # Only the single executable is extracted; archive paths are never used as destinations.
            with tempfile.NamedTemporaryFile(dir=destination, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(binary)
            try:
                temporary.chmod(0o755)
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
            saved = dict(record, archive_sha256=record['sha256'],
                         binary_sha256=hashlib.sha256(binary).hexdigest(), notices=notices)
            metadata.write_text(json.dumps(saved, indent=2), encoding='utf-8')
            print('  installed and SHA-256 verified', flush=True)
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            failed.append(name)
            print(f'  FAILED: {error}', flush=True)
    activate()
    print('Managed engine directory: ' + str(destination), flush=True)
    if failed:
        print('Retry setup-engines for: ' + ', '.join(failed))
    return 1 if failed else 0
