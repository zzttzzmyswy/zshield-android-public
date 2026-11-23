"""Host-only entry-point checks. All adb/curl calls use temporary doubles."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parent / 'zshield-android'
sys.path.insert(0, str(REPO / 'scripts/effectiveness/tests'))
from test_acceptance_entry import StubDevice

with tempfile.TemporaryDirectory(prefix='zs-condition-review-') as tmp:
    root = Path(tmp)
    tree = root / 'repo'
    shutil.copytree(REPO / 'scripts/effectiveness', tree / 'scripts/effectiveness')
    for case, command in [('no_lock_cleanup', 'cleanup'), ('failed_backup_install', 'apply-test-lists')]:
        device = StubDevice(root / case)
        before = device.rules.read_bytes()
        for name, body in [('sleep', '#!/bin/sh\nexit 0\n'), ('curl', '#!/bin/sh\nprintf "||probe.example^\\n"\n')]:
            p = device.bin / name; p.write_text(body); p.chmod(0o755)
        py = device.bin / 'python3'
        py.write_text(f'#!{sys.executable}\nimport os,sys\nif "capture" in sys.argv: raise SystemExit(2)\nos.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n')
        py.chmod(0o755)
        env = {**os.environ, 'PATH': f'{device.bin}:{os.environ["PATH"]}', 'OUT': str(root/case/'out'), 'SERIAL':'stub', 'LOCK_PATH': str(device.lock), 'LOCK_OWNER':'review-condition'}
        for k in ['LOCK_LOST_FILE', 'LOCK_TOKEN', 'LOCK_STATE_DIR', 'LOCK_GUARD_DIR']:
            env.pop(k, None)
        if command == 'cleanup':
            device.lock.write_text('OTHER-ACTIVE ' + time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + '\n')
        result = subprocess.run(['bash', str(tree/'scripts/effectiveness/condition.sh'), command], env=env, capture_output=True, text=True, timeout=45)
        calls = device.commands()
        # Decode actual device-side rule installation bodies as well as literal broadcasts.
        import base64, re
        decoded = []
        for call in device.calls():
            m=re.search(r'echo ([A-Za-z0-9+/=]+) \| base64 -d', ' '.join(call))
            if m: decoded.append(base64.b64decode(m.group(1)).decode())
        writes = ('DEBUG_SET_RULES' in calls) or any('DEBUG_SET_RULES' in body for body in decoded)
        print(f'{case}: exit={result.returncode}; attempted_rule_write={writes}; original_preserved={device.rules.read_bytes()==before}')
        print('restore_failure_reported:', 'NOT restored' in result.stdout + result.stderr or 'REFUSED' in result.stdout + result.stderr)
        (Path(__file__).parent / f'condition-{case}.log').write_text(result.stdout+result.stderr)

# This exact shell construct is used by condition.sh/pss_idle.sh EXIT handlers.
result=subprocess.run(['bash','-c','on_exit() { local code=$?; code=1; return "$code"; }; trap on_exit EXIT; true'], capture_output=True)
print(f'exit_trap_return_failure: process_exit={result.returncode} (expected nonzero)')
