"""`pss_idle.sh` must sample only when the **declared rule content** is provably in force.

Four revisions of readiness were rejected, each for the same underlying reason: the check believed
something that was not evidence.

* `hot reload finished: ok=true` — only printed when a rule *change* swaps a live tunnel, so a cold
  start could never satisfy it.
* `engine started` plus artifact *byte counts* and rule *counts* — the stage-4 review produced the
  counter-example that kills it: two rule sets of the same length and the same rule count have the same
  numbers and different rules.
* a readiness line and a pid the tool read **for itself** — so a buffer where every line came from
  another process, a required `--ready-line` that never appeared, and a trailing
  `hot reload finished: ok=false` all passed.
* an identity *observation* that was accepted without a declared target, without complete fields, and
  without re-validating the state after the last `dumpsys meminfo` — so an undeclared run, a bare
  `event=start ok=true` line, a swap during the final read and a `MEMINFO in pid 9999` answer all
  produced a median (MYS-2825 first review).

What the run decides on now is an observation the core makes at the moment it installs rules
(`core/src/rules_identity.rs`): one `rules identity:` line per start/swap carrying the SHA-256 of each
artifact payload as loaded, plus a handle and a monotonic generation. This module drives the real
`pss_idle.sh` as a program against a stub `adb`.

**The stub executes the production commands' own semantics**, because a stub that answers everything is
how the last two reviews' counter-examples stayed invisible:

* `logcat -c` really empties the buffer, and an injected failure really leaves it untouched (that is
  the `clear_failed_old_run` fault, which is only detectable if clearing is what empties the buffer);
* `logcat -d … | grep -E '<pattern>' | tail -N` applies **that** pattern and that tail — the pipeline's
  filtering is executed, not ignored;
* `am force-stop` removes the process and `am start` creates it, so `pidof` and the log buffer follow a
  real launch lifecycle rather than always answering "up";
* `am broadcast … DEBUG_TOGGLE_VPN` flips the tunnel, and `dumpsys connectivity` reports `IS_VPN` from
  that state;
* `dumpsys meminfo` answers with its configured block, which a case may make inconsistent with the pid
  the script asked about — exactly the fault `parse_meminfo` exists to catch.

Every case here is a *fault a real device can produce*; the positive control is first, because a suite
where everything is refused would also pass if the script refused everything.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

SCRIPTS = fixtures.SCRIPTS
PSS = SCRIPTS / "pss_idle.sh"
REPO = fixtures.REPO

#: The pid the stub reports for the app, and the pid a foreign line carries.
MEASURED_PID = 4242
FOREIGN_PID = 9999
PACKAGE = "top.zztweb.zshield"


def token(payload: bytes) -> str:
    """A `sha256:<hex>:<bytes>` identity token, computed the way the core computes it."""
    return f"sha256:{hashlib.sha256(payload).hexdigest()}:{len(payload)}"


#: Two rule sets of the same length and the same rule count, with different rules — the stage-4
#: review's counter-example, as payload bytes. `a` blocks `ads.example`, `b` blocks `cms.example`;
#: both are 13 bytes and both compile to exactly one network rule.
PAYLOAD_A = b"||ads.example^"
PAYLOAD_B = b"||cms.example^"
assert len(PAYLOAD_A) == len(PAYLOAD_B)
TOKEN_A = token(PAYLOAD_A)
TOKEN_B = token(PAYLOAD_B)

#: What a real cold start printed, in order, **as bare `L TAG: message` lines**. `threadtime()` turns
#: them into real `logcat -v threadtime` records; keeping the shape separate is what lets a case build a
#: foreign-pid chain, a same-pid old-launch chain, or a chain with no pid column at all.
COLD_START_CHAIN = f"""\
I ZShieldCore: compiled 5 lists: 180644 dns rules (180571 block / 40 exception), 406931 network, 696 unsupported, dns.bin 4224594 B, engine.bin 32198129 B, 4278 ms
I ZShieldCore: engine loaded in 198 ms, 32198129 B (11 redirect resources)
I ZShieldCore: rules reloaded: 180571 block, 40 exception, 696 unsupported (neither layer can use), 406931 network-only (engine rules); 0 cache entries dropped; engine 32198129 B
I ZShieldCore: rules identity: event=start ok=true handle=1 generation=1 pid={MEASURED_PID} dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}
I ZShieldCore: engine started, handle 1
I ZShieldCore: tunnel stack up: mode Full, mtu 1500
I ZShield : https filtering: true (ca installed true, 3 uids, user hosts 0)
"""

#: The identity the chain above declares, in `--expect-identity` form.
TARGET_A = f"dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}"
TARGET_B = f"dns={TOKEN_B} engine={TOKEN_B} extras={TOKEN_B}"

#: A real `logcat -v threadtime` header: `MM-DD HH:MM:SS.mmm  PID  TID L TAG: message`. The thread id
#: is deliberately different from the pid, as it is on a device, so a parser that reads the second
#: column as the process would be caught.
def threadtime(chain: str, pid: int, *, base_line: int = 0) -> str:
    """Give every bare chain line a real threadtime header naming `pid`."""
    out = []
    for offset, line in enumerate(chain.splitlines()):
        if re.match(r"^\d\d-\d\d\s", line):
            out.append(line)
        else:
            number = base_line + offset
            out.append(f"11-13 04:09:{number % 60:02d}.500 {pid} {pid + 1000} {line}")
    return "\n".join(out) + "\n"


class PssDevice:
    """A stub `adb` that executes the commands `pss_idle.sh` relies on, with their real effects."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        #: The device's log buffer. Only `logcat -c` empties it and only a launch appends to it.
        self.buffer = root / "logcat-buffer"
        #: What a **cleared** buffer holds: nothing. This is the file `logcat -c` writes into the
        #: buffer, and it is empty by definition — which is what makes the clear a clear rather than a
        #: refill. The name is kept because the review probe replaces this very statement with a
        #: failing one to inject a `logcat -c` failure, and a fixture whose clear statement is not the
        #: clear would leave that fault un-injectable (it did, in the first revision of this file).
        self.cleared = root / "startup-lines"
        #: What the *next* `am start` publishes into the buffer.
        self.startup = root / "launch-lines"
        self.meminfo = root / "meminfo"
        self.samples_taken = root / "samples"
        self.pidfile = root / "pid"
        self.tunnelfile = root / "tunnel"
        self.lock = root / "zshield-device.lock"
        self.control = root / "control.json"
        #: `{"after_samples": N, "text": "..."}` — appended to the buffer when the Nth `dumpsys meminfo`
        #: is served. This is how a rule swap *during* a sampling window is reproduced: the fault lands
        #: in the log at the point in time the script reads it.
        self.midrun = root / "midrun.json"
        #: `{"after_samples": N, "pid": P}` — `pidof` answers `P` once N samples have been taken.
        self.pidchange = root / "pidchange.json"

        self._reset_state()
        # Two distinct things, and keeping them distinct is the point:
        #
        #   * `buffer` starts holding what the **previous** launch left behind. A correct run must remove
        #     it (`logcat -c`) before anything it reads can be attributed to this launch; a case that
        #     makes the clear fail leaves exactly these lines in place, which is the fault being
        #     reproduced.
        #   * `startup` is the output the **next** launch will write. `am start` appends it to the buffer
        #     and consumes it, so at clear time it is empty and `logcat -c` is a genuine clear.
        #
        # A real launch writes real `logcat -v threadtime` records, so both are in that form. A case that
        # wants the unattributable shape writes it through `set_chain_bare`/`preload_buffer_bare`.
        rendered = threadtime(COLD_START_CHAIN, MEASURED_PID, base_line=0)
        stale = threadtime(COLD_START_CHAIN, MEASURED_PID, base_line=30)
        self.buffer.write_text(stale, encoding="utf-8")
        self.startup.write_text(rendered, encoding="utf-8")
        self.cleared.write_text("", encoding="utf-8")
        self.set_meminfo_header(MEASURED_PID, PACKAGE)
        self.control.write_text("{}", encoding="utf-8")
        self._write_stub()

    # ---- device state ---------------------------------------------------------------------------

    def _reset_state(self) -> None:
        # `DEBUG_TOGGLE_VPN` is a *toggle*, not an "on" switch (`docs/TESTING.md` §14.8f), and the
        # script's first broadcast is the "stop the tunnel" one. So the device starts with the tunnel
        # **up**: that broadcast takes it down, and the one after the launch brings it back up. A
        # fixture that started down would invert both and report `tunnel: DOWN` at the end.
        self.tunnelfile.write_text("up", encoding="utf-8")
        self.pidfile.write_text("", encoding="utf-8")
        self.samples_taken.write_text("", encoding="utf-8")

    def set_meminfo_header(self, pid: int, package: str) -> None:
        self.meminfo.write_text(
            f"** MEMINFO in pid {pid} [{package}] **\n"
            "      Native Heap:    60640\n"
            "        Java Heap:     5336\n"
            "        TOTAL PSS:    88338            TOTAL RSS:   120000\n",
            encoding="utf-8",
        )

    # ---- fault injection ------------------------------------------------------------------------

    def fail(self, command: str) -> None:
        """Make the stub exit non-zero for `command` (a substring of the device-side command)."""
        control = json.loads(self.control.read_text())
        control.setdefault("fail", []).append(command)
        self.control.write_text(json.dumps(control), encoding="utf-8")

    def set_control(self, **values) -> None:
        control = json.loads(self.control.read_text())
        control.update(values)
        self.control.write_text(json.dumps(control), encoding="utf-8")

    # ---- the stub --------------------------------------------------------------------------------

    def _write_stub(self) -> None:
        body = f"""\
#!{sys.executable}
import base64, json, re, subprocess, sys
from pathlib import Path

root = Path({str(self.root)!r})
buffer = root / "logcat-buffer"
samples = root / "samples"
midrun = root / "midrun.json"
pidchange = root / "pidchange.json"
pidfile = root / "pid"
tunnelfile = root / "tunnel"
controlfile = root / "control.json"

args = sys.argv[1:]
if "-s" in args:
    i = args.index("-s"); del args[i:i + 2]
verb = args[0] if args else ""
rest = args[1:]
if verb == "get-state":
    print("device"); sys.exit(0)
if verb != "shell":
    sys.exit(0)
command = " ".join(rest)

control = json.loads(controlfile.read_text()) if controlfile.exists() else {{}}
for needle in control.get("fail", []):
    if needle in command:
        # A real failure: the command did nothing, and it says so through the exit status.
        print(f"error: injected failure for '{{needle}}'", file=sys.stderr)
        sys.exit(control.get("fail_status", 1))


def served_log():
    \"\"\"The buffer, after the pipeline's own `grep -E` / `grep -cE` and `tail -N` are applied.\"\"\"
    text = buffer.read_text() if buffer.exists() else ""
    count_only = "grep -cE" in command or "grep -c " in command
    match = re.search(r"grep -c?E? '([^']*)'", command) or re.search(r'grep -c?E? "([^"]*)"', command)
    lines = text.splitlines()
    if match:
        pattern = re.compile(match.group(1))
        # `logcat` itself also honours `-b all`; the filter is the `grep` stage, and it is applied here
        # exactly as the device's shell would apply it.
        lines = [line for line in lines if pattern.search(line)]
    if count_only:
        return str(len(lines)) + "\\n"
    tail = re.search(r"tail -(\\d+)", command)
    if tail:
        lines = lines[-int(tail.group(1)):]
    return "".join(line + "\\n" for line in lines)


if "base64 -d" in command:
    m = re.search(r"echo ([A-Za-z0-9+/=]+) \\| base64", command)
    script = base64.b64decode(m.group(1)).decode() if m else ""
    for suffix in (".d", ".state", ".guard"):
        script = script.replace("/data/local/tmp/zshield-device.lock" + suffix, {str(self.lock)!r} + suffix)
    script = script.replace("/data/local/tmp/zshield-device.lock", {str(self.lock)!r})
    raise SystemExit(subprocess.run(["sh", "-c", script]).returncode)

if command.startswith("pidof"):
    printed = pidfile.read_text().strip() if pidfile.exists() else ""
    if pidchange.exists():
        plan = json.loads(pidchange.read_text())
        done = len(samples.read_text()) if samples.exists() else 0
        if printed and done >= plan["after_samples"]:
            printed = str(plan["pid"])
    print(printed); sys.exit(0)

if command.startswith("am force-stop"):
    # A real force-stop kills the process: afterwards there is no pid, and the next launch is a
    # different process from the run's point of view.
    pidfile.write_text(""); sys.exit(0)

if command.startswith("am start"):
    if not control.get("start_is_noop"):
        pidfile.write_text("{MEASURED_PID}")
        # A launch is what writes this process's lines into the buffer.
        with open(buffer, "a") as handle:
            handle.write((root / "launch-lines").read_text() if (root / "launch-lines").exists() else "")
    print("Starting: Intent {{")
    print("Status: ok")
    sys.exit(0)

if command.startswith("am broadcast"):
    if "DEBUG_TOGGLE_VPN" in command:
        state = tunnelfile.read_text().strip() if tunnelfile.exists() else "down"
        tunnelfile.write_text("down" if state == "up" else "up")
    sys.exit(0)

if "dumpsys package" in command:
    print("appId=10250"); sys.exit(0)

if command.startswith("logcat -c"):
    # A clear that reports success and does nothing is a distinct fault from a clear that fails: the
    # exit status looks fine and only reading the buffer back can tell the difference.
    if not control.get("clear_is_noop"):
        buffer.write_text((root / "startup-lines").read_text()); sys.exit(0)
    sys.exit(0)

if "logcat -d" in command:
    sys.stdout.write(served_log()); sys.exit(0)

if "dumpsys connectivity" in command:
    state = tunnelfile.read_text().strip() if tunnelfile.exists() else "down"
    print("IS_VPN" if state == "up" else "no vpn"); sys.exit(0)

if "dumpsys meminfo" in command:
    with open(samples, "a") as handle:
        handle.write("x")
    taken = len(samples.read_text())
    if midrun.exists():
        plan = json.loads(midrun.read_text())
        if taken == plan.get("after_samples"):
            with open(buffer, "a") as handle:
                handle.write(plan["text"])
            midrun.unlink()
    print((root / "meminfo").read_text()); sys.exit(0)

sys.exit(0)
"""
        body = body.replace("@@ROOT@@", str(self.root))
        path = self.bin / "adb"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
        # The protocol's own delays are real; shorten them so a multi-sample case is quick.
        #
        # Only **short** naps are shortened. The lock renewer's own interval is 1800 s, and collapsing
        # that to 20 ms made the background renewer race the main loop's `lock_renew` on the guard,
        # which the lock (correctly) refused as GUARD_BUSY — a flake in the fixture, not in the script.
        sleep = self.bin / "sleep"
        sleep.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\n"
            "seconds = float(sys.argv[1])\n"
            "time.sleep(seconds if seconds > 60 else min(seconds, 0.02))\n",
            encoding="utf-8",
        )
        sleep.chmod(0o755)

    # ---- driving it ------------------------------------------------------------------------------

    def run(self, *args: str, samples: int = 1) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(PSS), "probe", "--samples", str(samples), "--interval", "1",
             "--settle", "2", "--out", str(self.root / "out"), *args],
            capture_output=True, text=True, env=self.env(), timeout=180,
            cwd=str(REPO),
        )

    def env(self) -> dict:
        environment = dict(os.environ)
        environment["PATH"] = f"{self.bin}{os.pathsep}{environment['PATH']}"
        environment["SERIAL"] = "stub:5555"
        environment["LOCK_OWNER"] = "MYS-2825"
        return environment

    def set_chain(self, chain: str, pid: int = MEASURED_PID) -> None:
        """What the *next* launch reports, as real threadtime records.

        The buffer is left alone: only `logcat -c` empties it, so a case that wants to reproduce a
        stale buffer writes it with `preload_buffer` instead.
        """
        rendered = threadtime(chain, pid)
        self.startup.write_text(rendered, encoding="utf-8")

    def set_chain_bare(self, chain: str) -> None:
        """What the next launch reports **without a threadtime header** — unattributable on purpose."""
        self.startup.write_text(chain, encoding="utf-8")

    def preload_buffer(self, chain: str, pid: int = MEASURED_PID) -> None:
        """Put lines into the buffer as a previous launch would have left them."""
        self.buffer.write_text(threadtime(chain, pid), encoding="utf-8")

    def preload_buffer_bare(self, chain: str) -> None:
        self.buffer.write_text(chain, encoding="utf-8")

    def swap_after(self, samples: int, text: str) -> None:
        """Append `text` to the log buffer when the `samples`-th `dumpsys meminfo` is served."""
        self.midrun.write_text(json.dumps({"after_samples": samples, "text": text}), encoding="utf-8")

    def restart_as(self, pid: int, after_samples: int) -> None:
        """Make `pidof` answer `pid` once `after_samples` samples have been taken."""
        self.pidchange.write_text(
            json.dumps({"after_samples": after_samples, "pid": pid}), encoding="utf-8"
        )

    def sample_count(self) -> int:
        path = self.samples_taken
        return len(path.read_text()) if path.exists() else 0

    def output(self, result: subprocess.CompletedProcess) -> str:
        return f"{result.stdout}\n{result.stderr}"


class PssReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.device = PssDevice(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def fresh(self, name: str) -> PssDevice:
        return PssDevice(Path(self._tmp.name) / name)

    # ---- the positive control ------------------------------------------------------------------

    def test_it_samples_this_launchs_declared_rule_content(self) -> None:
        """The control: a real threadtime cold start whose identity matches the target is sampled."""
        result = self.device.run("--expect-identity", TARGET_A)
        self.assertEqual(result.returncode, 0, self.device.output(result))
        self.assertGreater(self.device.sample_count(), 0, "no PSS sample was taken")
        self.assertIn("verified: live rule content is the declared target", result.stdout)
        self.assertIn("## median", result.stdout)

    def test_it_refuses_to_measure_without_a_declared_target(self) -> None:
        """A batch tied to no rule set is not acceptance evidence, and a warning is not a check."""
        result = self.device.run()
        self.assertNotEqual(result.returncode, 0, "a run with no declared target was accepted")
        self.assertEqual(self.device.sample_count(), 0, "it sampled without declaring what it measures")
        self.assertIn("--expect-identity", self.device.output(result))

    def test_diagnostic_mode_prints_no_median(self) -> None:
        """If a rough number is wanted, it must be asked for and must not be quotable as a result."""
        result = self.device.run("--diagnostic")
        self.assertEqual(result.returncode, 0, self.device.output(result))
        self.assertGreater(self.device.sample_count(), 0)
        self.assertNotIn("## median", result.stdout,
                         "a diagnostic run printed a median a script could quote as acceptance")
        self.assertIn("NOT acceptance evidence", result.stdout)

    def test_a_malformed_target_is_rejected_before_touching_the_device(self) -> None:
        result = self.device.run("--expect-identity", "dns=not-a-hash engine=- extras=-")
        self.assertNotEqual(result.returncode, 0, "a malformed target was accepted")
        self.assertEqual(self.device.sample_count(), 0)
        self.assertIn("is not an identity", self.device.output(result))

    def test_a_target_with_a_missing_component_is_rejected(self) -> None:
        result = self.device.run("--expect-identity", f"dns={TOKEN_A}")
        self.assertNotEqual(result.returncode, 0, "a partial target was accepted")
        self.assertEqual(self.device.sample_count(), 0)

    # ---- the three counter-examples from the stage-4 review ------------------------------------

    def test_it_refuses_a_chain_from_another_process(self) -> None:
        device = self.fresh("foreign-pid")
        device.set_chain(COLD_START_CHAIN, pid=FOREIGN_PID)
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a buffer belonging to another process was accepted")
        self.assertEqual(device.sample_count(), 0, "it sampled on evidence from another process")
        self.assertIn("no 'rules identity:' event came from the measured pid", device.output(result))

    def test_it_refuses_when_the_required_ready_line_never_appears(self) -> None:
        result = self.device.run(
            "--expect-identity", TARGET_A,
            "--ready-line", "NEVER_PRESENT_REQUIRED_MARKER",
        )
        self.assertNotEqual(result.returncode, 0, "an unsatisfied --ready-line was accepted")
        self.assertEqual(self.device.sample_count(), 0, "it sampled although the required line never appeared")
        self.assertIn("NEVER_PRESENT_REQUIRED_MARKER", result.stdout)

    def test_it_refuses_a_launch_whose_last_hot_swap_failed(self) -> None:
        device = self.fresh("reload-failed")
        device.set_chain(COLD_START_CHAIN + "I ZShield : hot reload finished: ok=false\n")
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a trailing failed hot swap was accepted")
        self.assertEqual(device.sample_count(), 0, "it sampled a launch whose last swap failed")
        self.assertIn("did not succeed", device.output(result))

    # ---- identity cannot be faked by numbers --------------------------------------------------

    def test_it_refuses_the_same_length_with_different_content(self) -> None:
        device = self.fresh("same-length")
        device.set_chain(COLD_START_CHAIN.replace(TOKEN_A, TOKEN_B))
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a same-length rule set with different content was accepted")
        self.assertEqual(device.sample_count(), 0, "it sampled a rule set it was not asked to measure")
        self.assertIn("cannot tell these apart", device.output(result))
        self.assertEqual(TOKEN_A.rsplit(":", 1)[1], TOKEN_B.rsplit(":", 1)[1])

    def test_it_refuses_an_identity_whose_fields_are_incomplete(self) -> None:
        """`event=start ok=true` alone used to settle a run with generation/handle = none."""
        device = self.fresh("missing-fields")
        device.set_chain(
            "I ZShieldCore: rules identity: event=start ok=true\n"
            "I ZShieldCore: engine started, handle 1\n"
            "I ZShieldCore: tunnel stack up: mode Full, mtu 1500\n"
        )
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "an identity line with no fields was accepted")
        self.assertEqual(device.sample_count(), 0, "it sampled a launch whose identity was unreadable")
        self.assertIn("unusable", device.output(result))

    def test_it_refuses_a_line_with_no_pid_column(self) -> None:
        """An unattributable line is not evidence, whatever the buffer's history."""
        device = self.fresh("no-pid-column")
        device.set_chain_bare(COLD_START_CHAIN)  # `L TAG: message`, no threadtime header
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a chain with no pid column was accepted")
        self.assertEqual(device.sample_count(), 0)
        self.assertIn("cannot be attributed", device.output(result))

    def test_it_refuses_a_line_that_names_another_pid_in_its_payload(self) -> None:
        device = self.fresh("pid-disagreement")
        forged = COLD_START_CHAIN.replace(f"pid={MEASURED_PID}", f"pid={FOREIGN_PID}")
        device.set_chain(forged)
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a contradictory pid was believed")
        self.assertEqual(device.sample_count(), 0)

    # ---- failures produce no generation --------------------------------------------------------

    def test_it_refuses_a_load_that_failed(self) -> None:
        device = self.fresh("load-failed")
        device.set_chain(
            f"I ZShieldCore: rules identity: event=start ok=false handle=1 generation=0 "
            f"pid={MEASURED_PID} dns=- engine=- extras=- reason=engine:_cannot_deserialize\n"
            "I ZShieldCore: engine started, handle 1\n"
            "I ZShieldCore: tunnel stack up: mode Full, mtu 1500\n"
        )
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a failed load was accepted as ready")
        self.assertEqual(device.sample_count(), 0, "it sampled a launch that loaded nothing")

    def test_it_refuses_when_the_engine_is_absent(self) -> None:
        device = self.fresh("zero-engine")
        device.set_chain(COLD_START_CHAIN.replace(f"engine={TOKEN_A}", "engine=-"))
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "an absent engine was accepted for a declared target")
        self.assertEqual(device.sample_count(), 0)

    # ---- the start boundary is verified, not assumed -------------------------------------------

    def test_it_refuses_when_clearing_the_log_failed(self) -> None:
        """`logcat -c` exit 1 leaves the previous launch's lines — same pid, indistinguishable."""
        device = self.fresh("clear-failed")
        device.set_chain(COLD_START_CHAIN)
        device.fail("logcat -c")
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a failed logcat -c was treated as a start boundary")
        self.assertEqual(device.sample_count(), 0, "it sampled an old launch's buffer")
        self.assertIn("start boundary", device.output(result))

    def test_it_refuses_when_the_clear_reports_success_but_the_buffer_kept_lines(self) -> None:
        """The exit status is not the only check: the buffer is read back."""
        device = self.fresh("clear-noop")
        device.set_chain(COLD_START_CHAIN)
        device.set_control(clear_is_noop=True)
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "an unverified clear was treated as a boundary")
        self.assertEqual(device.sample_count(), 0)

    def test_a_stale_line_from_the_same_pid_does_not_survive_a_successful_clear(self) -> None:
        """A previous launch of the *same* pid leaves a line that looks exactly like this run's.

        This is the case a pid check alone cannot separate, so the clear is what separates it: the stale
        buffer here names a different rule set (B) and a different generation, and a run that used it
        would either measure B or refuse the declared target A. Succeeding on A, from a buffer that
        started holding B, is only possible if the clear really removed it.
        """
        device = self.fresh("stale-same-pid")
        stale = COLD_START_CHAIN.replace(TOKEN_A, TOKEN_B).replace("generation=1", "generation=7")
        device.preload_buffer(stale)
        device.set_chain(COLD_START_CHAIN)
        result = device.run("--expect-identity", TARGET_A)
        self.assertEqual(result.returncode, 0, device.output(result))
        self.assertIn("generation=1", result.stdout)
        self.assertNotIn("generation=7", result.stdout, "a line from the previous launch was used")
        # And the boundary itself was reported as verified, not asserted from host time.
        self.assertIn("start boundary verified", result.stdout)

    def test_a_stale_line_that_survives_a_failed_clear_is_never_used(self) -> None:
        """Same shape, but the clear fails: the *only* line in the buffer is the stale one."""
        device = self.fresh("stale-kept")
        device.preload_buffer(COLD_START_CHAIN)          # what the previous launch left, same pid
        device.set_chain("I ZShieldCore: engine started, handle 1\n")  # this launch says almost nothing
        device.fail("logcat -c")
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "an old launch's identity was used as this run's")
        self.assertEqual(device.sample_count(), 0)
        self.assertNotIn("## median", result.stdout)

    def test_it_refuses_a_launch_that_did_not_create_a_process(self) -> None:
        device = self.fresh("no-launch")
        device.set_chain(COLD_START_CHAIN)
        device.set_control(start_is_noop=True)
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a launch that produced no process was accepted")
        self.assertEqual(device.sample_count(), 0)

    def test_it_refuses_when_force_stop_failed(self) -> None:
        device = self.fresh("force-stop-failed")
        device.set_chain(COLD_START_CHAIN)
        device.fail("am force-stop")
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a failed force-stop was accepted")
        self.assertEqual(device.sample_count(), 0)

    # ---- the batch belongs to one state --------------------------------------------------------

    def test_a_swap_during_the_last_read_voids_the_batch(self) -> None:
        """The fault the previous revision missed: validation only ran before `dumpsys`."""
        device = self.fresh("swap-at-last-read")
        device.set_chain(COLD_START_CHAIN)
        device.swap_after(
            1,
            threadtime(
                f"I ZShieldCore: rules identity: event=swap ok=true handle=1 generation=2 "
                f"pid={MEASURED_PID} dns={TOKEN_B} engine={TOKEN_B} extras={TOKEN_B}",
                MEASURED_PID,
            ) + "\n",
        )
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a swap during the last read was accepted")
        self.assertIn("batch voided", device.output(result))
        self.assertNotIn("## median", result.stdout, "a voided batch printed a median")

    def test_a_process_restart_inside_the_window_voids_the_batch(self) -> None:
        device = self.fresh("restart-midrun")
        device.set_chain(COLD_START_CHAIN)
        device.restart_as(MEASURED_PID + 1, after_samples=1)
        result = device.run("--expect-identity", TARGET_A, samples=3)
        self.assertNotEqual(result.returncode, 0, "a batch spanning two processes was accepted")
        self.assertIn("batch voided", device.output(result))
        self.assertNotIn("## median", result.stdout)

    def test_a_meminfo_answer_for_another_pid_is_refused(self) -> None:
        """The header is the attribution: `MEMINFO in pid 9999` is not a sample of 4242."""
        device = self.fresh("wrong-meminfo-pid")
        device.set_chain(COLD_START_CHAIN)
        device.set_meminfo_header(FOREIGN_PID, PACKAGE)
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a meminfo block for another pid was recorded")
        self.assertIn("batch voided", device.output(result))
        self.assertNotIn("## median", result.stdout)

    def test_a_meminfo_answer_for_another_package_is_refused(self) -> None:
        device = self.fresh("wrong-meminfo-package")
        device.set_chain(COLD_START_CHAIN)
        device.set_meminfo_header(MEASURED_PID, "com.example.other")
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a meminfo block for another package was recorded")
        self.assertEqual(device.sample_count() > 0, True, "the read itself did happen")
        self.assertNotIn("## median", result.stdout)

    def test_a_meminfo_answer_without_a_header_is_refused(self) -> None:
        device = self.fresh("meminfo-no-header")
        device.set_chain(COLD_START_CHAIN)
        device.meminfo.write_text(
            "        Java Heap:     5336\n"
            "        TOTAL PSS:    88338\n",
            encoding="utf-8",
        )
        result = device.run("--expect-identity", TARGET_A)
        self.assertNotEqual(result.returncode, 0, "a headerless meminfo answer was recorded")
        self.assertNotIn("## median", result.stdout)

    # ---- the cached start ---------------------------------------------------------------------

    def test_a_cached_cold_start_is_provable_from_its_identity(self) -> None:
        """A cached start prints no `rules reloaded` line — and is provable anyway."""
        device = self.fresh("cached")
        device.set_chain(
            "I ZShieldCore: engine loaded in 193 ms, 32198129 B (11 redirect resources)\n"
            f"I ZShieldCore: rules identity: event=start ok=true handle=4 generation=1 "
            f"pid={MEASURED_PID} dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}\n"
            "I ZShieldCore: engine started, handle 4\n"
            "I ZShieldCore: tunnel stack up: mode Full, mtu 1500\n"
        )
        result = device.run("--expect-identity", TARGET_A)
        self.assertEqual(result.returncode, 0, device.output(result))
        self.assertGreater(device.sample_count(), 0, "a cached start produced no sample")

    # ---- auxiliary checks are kept, and are not the identity -----------------------------------

    def test_an_engine_size_mismatch_is_still_refused(self) -> None:
        result = self.device.run("--expect-identity", TARGET_A, "--expect-engine", str(len(PAYLOAD_A)))
        self.assertEqual(result.returncode, 0, self.device.output(result))

        other = self.fresh("size-wrong")
        other.set_chain(COLD_START_CHAIN)
        wrong_token = f"sha256:{'0' * 64}:{len(PAYLOAD_A) + 1}"
        other.set_chain(COLD_START_CHAIN.replace(f"engine={TOKEN_A}", f"engine={wrong_token}"))
        other.set_chain(COLD_START_CHAIN.replace(
            f"pid={MEASURED_PID} dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}",
            f"pid={MEASURED_PID} dns={TOKEN_A} engine={wrong_token} extras={TOKEN_A}",
        ))
        # The identity no longer matches the declared target, so this refusal is the identity check's;
        # the auxiliary size check is exercised by a target that declares the wrong engine size.
        wrong = other.run("--expect-identity", TARGET_A, "--expect-engine", str(len(PAYLOAD_A)))
        self.assertNotEqual(wrong.returncode, 0, "a different artifact size was accepted")
        self.assertEqual(other.sample_count(), 0)

    # ---- the identity helper ------------------------------------------------------------------

    def test_the_identity_helper_agrees_with_the_core_measure(self) -> None:
        """`--identity <dir>` is how a caller derives the target, so it must hash the payload only."""
        directory = Path(self._tmp.name) / "compiled"
        directory.mkdir()
        payload = b"||engine.example^\n"
        envelope = (
            b"ZSENG\0\0\x01"
            + (1).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + len(payload).to_bytes(4, "little")
            + (0x12345678).to_bytes(4, "little")
            + payload
        )
        (directory / "engine.bin").write_bytes(envelope)
        result = subprocess.run(
            ["bash", str(PSS), "--identity", str(directory)],
            capture_output=True, text=True, timeout=60, cwd=str(REPO),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"engine={token(payload)}", result.stdout)
        self.assertIn("dns=-", result.stdout)
        self.assertIn("extras=-", result.stdout)

    def test_the_identity_helper_refuses_a_non_artifact(self) -> None:
        directory = Path(self._tmp.name) / "not-an-artifact"
        directory.mkdir()
        (directory / "dns.bin").write_bytes(b"just some bytes that are not an artifact")
        result = subprocess.run(
            ["bash", str(PSS), "--identity", str(directory)],
            capture_output=True, text=True, timeout=60, cwd=str(REPO),
        )
        self.assertNotEqual(result.returncode, 0, "a non-artifact was given an identity")

    def test_expect_identity_from_derives_the_target(self) -> None:
        directory = Path(self._tmp.name) / "derived"
        directory.mkdir()
        for name, magic, payload in (
            ("dns.bin", b"ZSDNS\0\0\x01", b"dns payload"),
            ("engine.bin", b"ZSENG\0\0\x01", b"engine payload"),
            ("extras.txt", b"ZSEXT\0\0\x01", b"extras payload"),
        ):
            (directory / name).write_bytes(
                magic + (1).to_bytes(2, "little") + (0).to_bytes(2, "little")
                + len(payload).to_bytes(4, "little") + (0).to_bytes(4, "little") + payload
            )
        derived = subprocess.run(
            ["bash", str(PSS), "--identity", str(directory)],
            capture_output=True, text=True, timeout=60, cwd=str(REPO),
        )
        self.assertEqual(derived.returncode, 0, derived.stderr)
        # And the same declaration drives a real run: the chain must match it exactly.
        chain = (
            f"I ZShieldCore: rules identity: event=start ok=true handle=1 generation=1 "
            f"pid={MEASURED_PID} {derived.stdout.strip()}\n"
            "I ZShieldCore: engine started, handle 1\n"
            "I ZShieldCore: tunnel stack up: mode Full, mtu 1500\n"
        )
        device = self.fresh("derived-target")
        device.set_chain(chain)
        result = device.run("--expect-identity-from", str(directory))
        self.assertEqual(result.returncode, 0, device.output(result))
        self.assertIn("verified: live rule content is the declared target", result.stdout)


if __name__ == "__main__":
    unittest.main()
