"""Host-only review probes: never contacts adb or the Pixel."""
import base64
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent / "zshield-android"
LIB = ROOT / "scripts/effectiveness/device-lock.sh"
with tempfile.TemporaryDirectory(prefix="zs-safety-review-") as tmp:
    d = Path(tmp)
    bindir = d / "bin"
    bindir.mkdir()
    adb = bindir / "adb"
    adb.write_text('''#!/usr/bin/env python3
import base64, os, re, subprocess, sys
encoded = re.search(r"echo ([A-Za-z0-9+/=]+) \\| base64 -d", sys.argv[-1]).group(1)
script = base64.b64decode(encoded).decode().replace('/data/local/tmp', os.environ['PROBE_DEVICE'])
raise SystemExit(subprocess.run(['sh', '-c', script]).returncode)
''')
    adb.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "PROBE_DEVICE": str(d), "LOCK_OWNER": "review", "LOCK_TOKEN": "A",
           # The tools have no default device serial; these probes use a stub adb, so the serial only
           # has to be present and unambiguous.
           "SERIAL": "stub:5555"}
    for key in ("LOCK_PATH", "LOCK_TTL"):
        env.pop(key, None)
    command = f'source "{LIB}"; lock_take'
    canonical = d / "zshield-device.lock"
    canonical.write_text("OTHER-ACTIVE-ISSUE " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    result = subprocess.run(["bash", "-c", command], env=env, capture_output=True, text=True, timeout=10)
    print(f"active_canonical_lock: take_exit={result.returncode}; canonical_unchanged={canonical.read_text().startswith('OTHER-ACTIVE-ISSUE')}; accepted={result.returncode == 0}")

    # Force both contenders to observe the same stale lock, but B's rename happens
    # after A has replaced it with a fresh lock. No probabilistic stress loop.
    lock = d / "race-lock"
    lock.mkdir()
    (lock / "meta").write_text("owner=old\nissued=1\nrenewed=1\ntoken=old\n")
    mv = bindir / "mv"
    mv.write_text('''#!/usr/bin/env python3
import os, pathlib, subprocess, sys, time
d = pathlib.Path(os.environ['PROBE_DEVICE'])
if sys.argv[-1].endswith('.stale.B'):
    (d/'ready').touch()
    deadline = time.monotonic()+10
    while not (d/'resume').exists():
        if time.monotonic()>deadline: raise SystemExit(3)
        time.sleep(.01)
raise SystemExit(subprocess.run(['/usr/bin/mv', *sys.argv[1:]]).returncode)
''')
    mv.chmod(0o755)
    race_env = {**env, "LOCK_PATH": str(lock)}
    b = subprocess.Popen(["bash", "-c", command], env={**race_env, "LOCK_TOKEN": "B"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic()+10
    while not (d / "ready").exists():
        if time.monotonic() > deadline:
            b.kill(); b.communicate(); raise RuntimeError("barrier not reached")
        time.sleep(.01)
    a = subprocess.run(["bash", "-c", command], env=race_env, capture_output=True, text=True, timeout=10)
    (d / "resume").touch()
    bout, berr = b.communicate(timeout=10)
    print(f"stale_takeover_interleaving: A_exit={a.returncode}; B_exit={b.returncode}; both_acquired={a.returncode == b.returncode == 0}; final_meta={(lock/'meta').read_text()!r}")

spec = importlib.util.spec_from_file_location("rules_backup", ROOT / "scripts/effectiveness/rules_backup.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class LiteralMarkerDevice:
    def start_debug_screen(self): pass
    def dump_ui(self): return '<hierarchy><node text="自定义规则：（空）" /></hierarchy>'
state = module.read_rules(LiteralMarkerDevice())
print(f"literal_marker_backup: original='（空）'; known={state['known']}; stored={state['rules']!r}; lossy={state['rules'] != '（空）'}")
