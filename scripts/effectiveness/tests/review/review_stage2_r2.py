import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
repo = root / 'zshield-android'
spec = importlib.util.spec_from_file_location('harness', repo / 'scripts/effectiveness/tunnel_concurrency.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
s = next(x for x in m.build_scenarios('https://echo.invalid', 'review-r2') if x['name'] == 'h2-get')
expected = s['expect']
echo = {'id': 'WRONG-UPSTREAM-ID', 'path': m.expected_upstream_path(s['url'], []),
        'method': 'GET', 'body': '', 'alpn': 'h2', 'tls': True}
result = {'id': 'expected-client-id', 'status': 200, 'url': s['url'], 'protocol': 'h2', 'body': json.dumps(echo)}
problems = m.check_one(result, {'run_id': 'review-r2'}, expected)
missed = int(not problems)
print(f'wrong_upstream_request_id: problems={problems}; missed={not problems}')

with tempfile.TemporaryDirectory(prefix='review-snapshot-', dir=root) as name:
    out = Path(name)
    (out / 'tunnel-snapshot-review-before.txt').write_text('pid=123\nuid=10001\nsockets= 1 01\n')
    for label, after in [('missing_after_socket_observation', 'pid=123\nuid=10001\n'),
                         ('fin_wait2_growth', 'pid=123\nuid=10001\nsockets= 1 01 1000 05\n')]:
        (out / 'tunnel-snapshot-review-settled-after.txt').write_text(after)
        r = subprocess.run(['bash', str(repo / 'scripts/effectiveness/tunnel_snapshot.sh'), 'check', 'review'],
                           env=os.environ | {'OUT': str(out)}, capture_output=True, text=True)
        print(f'{label}: exit={r.returncode}; {r.stdout.strip()}; {r.stderr.strip()}')
        missed += r.returncode == 0
print(f'{missed}/3 invalid observations falsely accepted')
raise SystemExit(1 if missed else 0)
