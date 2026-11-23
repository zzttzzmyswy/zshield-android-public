import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
repo = root / 'zshield-android'
spec = importlib.util.spec_from_file_location('stage3_harness', repo / 'scripts/effectiveness/tunnel_concurrency.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
scenarios = m.build_scenarios('https://echo.invalid', 'review3')
group = m.plan_group(scenarios, 20, 0)
peak = max(len(calls) for calls in group['legs'].values())
errors = m.validate_concurrency([group], [{'group': 0, 'inflight': peak}], 20)
print(f'under_20_concurrency: peak={peak}, legs={[len(x) for x in group["legs"].values()]}, errors={errors}')
failures = int(not errors)

with tempfile.TemporaryDirectory(prefix='review-stage3-', dir=root) as tmp:
    d = Path(tmp)
    (d / 'tunnel-snapshot-review-before.txt').write_text('pid=123\nuid=10001\nsockets= 1 01\n')
    (d / 'tunnel-snapshot-review-settled.txt').write_text('pid=123\nuid=10001\nsockets= 3 01\n')
    r = subprocess.run(['bash', str(repo / 'scripts/effectiveness/tunnel_snapshot.sh'), 'check', 'review'],
                       env=os.environ | {'OUT': str(d)}, capture_output=True, text=True)
    print(f'no_run_metadata_app_connections_plus2: exit={r.returncode}; {r.stdout.strip()}; {r.stderr.strip()}')
    failures += r.returncode == 0

    state = d / 'user-rules'
    state.write_text('ORIGINAL_USER_RULES')
    log = d / 'adb-log'
    stub = '#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['PROBE_LOG'], 'a') as f: f.write(json.dumps(args)+'\\n')
s = ' '.join(args)
if 'get-state' in args: print('device')
elif 'dumpsys connectivity' in s: print('IS_VPN')
elif 'DEBUG_SET_RULES' in s:
    Path(os.environ['PROBE_STATE']).write_text('TEST_RULES_OVERWROTE_ORIGINAL')
    print('Broadcast completed: result=0')
elif 'cat /sdcard/zs-ui.xml' in s: print('<hierarchy/>')
'''
    (d / 'adb').write_text(stub)
    (d / 'python3').write_text('#!/bin/sh\nexit 1\n')
    (d / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    for name in ('adb', 'python3', 'sleep'): (d / name).chmod(0o755)
    env = os.environ | {'PATH': str(d)+os.pathsep+os.environ['PATH'], 'OUT': str(d),
                        'PROBE_LOG': str(log), 'PROBE_STATE': str(state)}
    env.pop('LOCK_OWNER', None)
    r = subprocess.run(['bash', str(repo / 'scripts/effectiveness/tunnel_acceptance.sh'),
                        '--origin', 'https://echo.invalid'], env=env, capture_output=True, text=True, timeout=15)
    changed = state.read_text() != 'ORIGINAL_USER_RULES'
    checked = 'zshield-device.lock' in log.read_text()
    print(f'backup_unavailable_and_no_lock_owner: exit={r.returncode}, user_rules_changed={changed}, lock_checked={checked}')
    print('restore_message: ' + next((x for x in r.stderr.splitlines() if 'NOT restored' in x), '<missing>'))
    failures += changed or not checked
print(f'{failures}/3 review cases failed')
raise SystemExit(1 if failures else 0)
