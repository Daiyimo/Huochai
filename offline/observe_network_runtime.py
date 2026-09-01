"""Record target process/endpoint snapshots during a real startup and idle run.

Packet/ETW capture must already be running. This script does not change network
policy, inject code, or replace the application. Endpoint snapshots supplement
ETW; they are not used to claim that short-lived connections cannot occur.
"""
import argparse
import datetime as dt
import hashlib
import json
import subprocess
import time
from pathlib import Path

import psutil


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--launch', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=610)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = args.launch.parent.resolve()
    start = time.monotonic()
    ready_at = None
    metadata = {'start_utc': utc(), 'duration_requested_seconds': args.seconds,
                'package': str(args.launch),
                'package_sha256': hashlib.sha256(args.launch.read_bytes()).hexdigest(),
                'sampling_interval_seconds': 2, 'observed_processes': {}}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    launched = subprocess.Popen([str(args.launch)], cwd=root, startupinfo=startup)
    metadata['wrapper_pid'] = launched.pid
    (args.output / 'idle-run.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    known = set()
    try:
        known.add((launched.pid, psutil.Process(launched.pid).create_time()))
    except psutil.NoSuchProcess:
        pass
    with (args.output / 'endpoint-snapshots.jsonl').open('x', encoding='utf-8') as stream:
        while True:
            snapshot = {'utc': utc(), 'elapsed_seconds': round(time.monotonic()-start, 3),
                        'processes': []}
            psutil.process_iter.cache_clear()
            current = list(psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'create_time']))
            identities = {p.info['pid']: (p.info['pid'], p.info['create_time']) for p in current}
            for process in current:
                info = process.info
                image = info.get('exe') or ''
                target_image = image.lower().startswith(str(root).lower() + '\\')
                identity = (info['pid'], info['create_time'])
                if not (target_image or identity in known or identities.get(info['ppid']) in known):
                    continue
                known.add(identity)
                item = dict(info)
                try:
                    item['status'] = process.status()
                    item['endpoints'] = [dict(family=int(c.family), type=int(c.type),
                                             local=list(c.laddr), remote=list(c.raddr), status=c.status)
                                         for c in process.net_connections(kind='inet')]
                except (psutil.AccessDenied, psutil.NoSuchProcess) as error:
                    item['snapshot_error'] = type(error).__name__
                snapshot['processes'].append(item)
                identity = str(info['pid']) + ':' + str(info['create_time'])
                if identity not in metadata['observed_processes']:
                    metadata['observed_processes'][identity] = dict(info, first_seen_utc=snapshot['utc'])
            stream.write(json.dumps(snapshot) + '\n')
            stream.flush()
            elapsed = time.monotonic() - start
            main_running = any(p['name'].lower() == 'huochat.exe' for p in snapshot['processes'])
            if ready_at is None and main_running:
                ready_at = time.monotonic()
                metadata['application_started_utc'] = utc()
                metadata['startup_seconds'] = round(ready_at-start, 3)
                print('Application started; beginning continuous idle timer.', flush=True)
            if ready_at is None and elapsed > 45:
                metadata['failure'] = 'Application did not start within 45 seconds; idle test invalid.'
                break
            if ready_at is not None and not main_running:
                metadata['failure'] = 'Application exited during idle observation; idle test invalid.'
                break
            idle_elapsed = time.monotonic()-ready_at if ready_at is not None else 0
            if idle_elapsed >= args.seconds:
                break
            if int(elapsed) // 60 != int(max(0, elapsed-2)) // 60:
                print(f'Idle capture: {int(elapsed)} seconds; target processes: {len(snapshot["processes"])}', flush=True)
            time.sleep(min(2, max(0.1,args.seconds-idle_elapsed)))
    metadata.update(end_utc=utc(), actual_elapsed_seconds=round(time.monotonic()-start, 3),
                    application_idle_seconds=round(time.monotonic()-ready_at,3) if ready_at else 0,
                    valid='failure' not in metadata)
    (args.output / 'idle-run.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print('Startup/idle observation:', metadata['application_idle_seconds'], 'seconds;',
          metadata.get('failure','valid'), flush=True)


if __name__ == '__main__':
    main()
