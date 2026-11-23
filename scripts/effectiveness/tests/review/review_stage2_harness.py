"""Offline review probes; no adb, browser, network, or device mutation."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types

path = Path(__file__).parent / 'zshield-android/scripts/effectiveness/tunnel_concurrency.py'
spec = importlib.util.spec_from_file_location('review_tunnel', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
scenarios = {s['name']: s for s in mod.build_scenarios('https://echo.invalid/anything', 'review-run')}

def result(body, protocol='h2'):
    return {'status': 200, 'url': 'https://echo.invalid/anything/get', 'protocol': protocol,
            'body': json.dumps(body), 'id': 'client-request-id'}

probes = [
    ('missing_h2_evidence', result({'url': 'https://echo.invalid/anything/get?keep=1&zs_rid=review-run', 'method': 'GET'}, ''), 'h2-get'),
    ('wrong_path_and_method', result({'url': 'https://echo.invalid/UNREQUESTED?keep=1&zs_rid=review-run', 'method': 'DELETE'}), 'h2-get'),
    ('corrupted_post_body', result({'url': 'https://echo.invalid/anything/post?keep=1&zs_rid=review-run', 'method': 'POST', 'data': 'alpha=1WRONG&beta=2WRONG'}), 'h1-post'),
]
missed = 0
for name, response, scenario in probes:
    problems = mod.check_one(response, {'run_id': 'review-run'}, scenarios[scenario]['expect'])
    missed += not problems
    print(f'{name}: {"MISSED" if not problems else "DETECTED"}; problems={problems}')

class FakePage:
    def evaluate(self, script, **kwargs):
        if script == 'location.href':
            return 'https://echo.invalid/'
        if 'navigation' in script:
            return 'h2'
        return '[]'  # An empty result batch must fail the count check.

class FakeBrowser:
    @staticmethod
    def attach(*args, **kwargs):
        return FakeBrowser()
    def open(self, *args, **kwargs):
        return FakePage()

sys.modules['cdp'] = types.SimpleNamespace(Browser=FakeBrowser)
sys.argv = ['tunnel_concurrency.py', '--origin', 'https://echo.invalid/anything', '--rounds', '5', '--concurrency', '20']
output = io.StringIO()
with contextlib.redirect_stdout(output):
    code = mod.main()
print(f'empty_result_batches: exit={code}; {output.getvalue().strip().splitlines()[-1]}')
missed += code == 0
print('h1_scenario_urls:', [scenarios[k]['url'] for k in ('h1-get', 'h1-post')])
print(f'{missed}/4 invalid results falsely accepted')
raise SystemExit(1 if missed else 0)
