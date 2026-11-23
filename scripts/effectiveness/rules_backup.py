#!/usr/bin/env python3
"""Capture and restore the app's user rules **byte for byte**, or refuse and change nothing.

Why this exists
---------------
The user rules live in app-private storage (`files/…`), and the release build is not debuggable, so
`run-as` is refused. The readable surfaces are the app's own screens, and the previous revision read the
*diagnostics* screen's `自定义规则：…` line. That line is rendered as
`FilterRepository.userRules.value.ifBlank { "（空）" }`, so it collapses **three** different rule sets
into one string:

    ""            (nothing)
    "   \\n\\t"      (whitespace only — `ifBlank` is true for it too)
    "（空）"        (a rule set that literally is those two characters)

The previous revision mapped the marker to the empty string and recorded `known: true`. The stage-3
safety probe measured the consequence: an original rule set of `（空）` was backed up as `""`, and the
"restore" then *deleted the user's rules*. Its word for that was `lossy=True`; `docs/TESTING.md` §14.6
called it "observable equivalence". Observable equivalence is not what a backup means.

The rules editor, by contrast, is seeded with the repository value itself —
`RulesEditorScreen.kt:57` `RulesKind.USER_RULES -> FilterRepository.userRules.value` — and renders it in
an editable text field. Reading *that* field returns the raw text, so empty, whitespace-only and the
literal marker are three distinct observations, and trailing newlines survive.

So this tool:

* reads the editor's text field (the **only** lossless surface), and requires exactly one editable node
  in the dump — anything else is refused rather than guessed at;
* refuses when that surface cannot be read, with `known: false` and a reason, and the caller then
  performs **zero** `DEBUG_SET_RULES` calls;
* keeps a `sha256` over the exact captured text, so a restore cannot install a backup that was edited or
  truncated after the fact;
* restores through the app's `DEBUG_SET_RULES` seam without losing a single byte — the rule text is
  pushed as a file and read on the device with a sentinel appended, because `"$(cat file)"` strips
  every trailing newline (the review's second loss) and an inline `--es` argument is re-parsed by the
  device's `sh`, which eats `$removeparam`, `|`, `*` and `(`;
* re-reads the editor afterwards and compares the **exact** text, newlines included, and reports a
  mismatch as a failure with the backup kept.

Usage
-----
    rules_backup.py capture  --out FILE [--source editor|debug]
    rules_backup.py restore  --from FILE
    rules_backup.py show     --from FILE

Exit codes: 0 success; 2 the rules could not be read, could not be restored, or the read was ambiguous
(nothing was changed on a failed capture; on a failed restore the caller is told what it left behind).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

# `device_serial` lives next to this file; the tools are run as scripts, not as an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import device_serial  # noqa: E402

DEFAULT_PACKAGE = os.environ.get("PKG", "top.zztweb.zshield")
#: The label `DebugActivity` prefixes the rules with (`R.string.debug_custom_rules_format`).
RULES_LABEL = "自定义规则："
#: What `DebugActivity` shows instead of a blank rule set (`userRules.ifBlank { … }`).
BLANK_MARKER = "（空）"
#: The bottom-navigation label of the filters tab, and the row that opens the rules editor.
FILTERS_TAB = "过滤器"
USER_RULES_ROW = "自定义规则"
#: Where the dump is written on the device. `/sdcard` needs no permission the shell lacks.
DUMP_PATH = "/sdcard/zs-ui.xml"
#: Where a restore's rule text is staged on the device.
REMOTE_RULES = "/data/local/tmp/zs-restore-rules.txt"


def say(message: str) -> None:
    print(message, flush=True)


class Device:
    """The `adb` calls this tool needs, each of which may fail loudly."""

    def __init__(self, serial: str, package: str) -> None:
        self.serial = serial
        self.package = package

    def shell(self, command: str, timeout: float = 60.0) -> str:
        result = subprocess.run(
            ["adb", "-s", self.serial, "shell", command],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"adb shell {command[:60]!r} failed ({result.returncode}): {result.stderr.strip()[:200]}"
            )
        return result.stdout.replace("\r", "")

    def start_debug_screen(self) -> None:
        # `am start` reports failure on stderr while exiting 0, so its output is checked rather than
        # its status: a screen that never opened would otherwise read as "no rules".
        out = self.shell(f"am start -n {self.package}/.debug.DebugActivity 2>&1")
        if "Error" in out or "does not exist" in out:
            raise RuntimeError(f"could not open the debug screen: {out.strip()[:200]}")
        time.sleep(2.0)

    def start_main_screen(self) -> None:
        out = self.shell(f"am start -W -n {self.package}/.ui.MainActivity 2>&1")
        if "Error" in out or "does not exist" in out:
            raise RuntimeError(f"could not open the app: {out.strip()[:200]}")
        time.sleep(2.5)

    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {x} {y}")
        time.sleep(1.5)

    def back(self) -> None:
        # Leaving the editor is bookkeeping, not part of the read: a failed `back` (an unplugged
        # device, a dead adbd) must not replace the reason the read failed with a message about the
        # keyevent that tried to clean up.
        try:
            self.shell("input keyevent KEYCODE_BACK")
        except (RuntimeError, OSError):
            pass
        time.sleep(0.8)

    def dump_ui(self) -> str:
        """Return the current `uiautomator` XML, or raise."""
        self.shell(f"rm -f {DUMP_PATH}")
        out = self.shell(f"uiautomator dump {DUMP_PATH} 2>&1")
        if "dumped to" not in out and "UI hierchary dumped" not in out and DUMP_PATH not in out:
            # `uiautomator` prints its own confirmation; anything else means the dump did not happen.
            if "ERROR" in out.upper() or "could not" in out.lower():
                raise RuntimeError(f"uiautomator dump failed: {out.strip()[:200]}")
        xml = self.shell(f"cat {DUMP_PATH} 2>/dev/null")
        if not xml.strip():
            raise RuntimeError(f"{DUMP_PATH} is empty; the UI dump did not produce a hierarchy")
        return xml


def _nodes(root: ElementTree.Element):
    yield root
    for child in root:
        yield from _nodes(child)


def _texts(root: ElementTree.Element) -> list[str]:
    """Every `text` attribute in the tree, entities already decoded by the parser.

    This is why the dump is parsed as XML rather than scraped: `&lt;` arrives as `<`, `&#10;` as a
    newline, and a multi-line value is one attribute rather than several lines to be guessed apart.
    """
    return [node.get("text") or "" for node in _nodes(root)]


def _bounds(node: ElementTree.Element) -> tuple[int, int, int, int] | None:
    raw = node.get("bounds") or ""
    # `bounds="[0,0][1080,200]"` -> (0, 0, 1080, 200)
    digits = raw.replace("][", ",").strip("[]").split(",")
    if len(digits) != 4:
        return None
    try:
        return tuple(int(value) for value in digits)  # type: ignore[return-value]
    except ValueError:
        return None


def _tap_node(device: "Device", text: str, *, lowest: bool = False) -> bool:
    """Tap the node whose `text` is exactly `text`.

    `lowest` picks the bottom-most match: the filters tab label also appears as a page heading, and the
    tab that navigates is the one in the bottom bar. This is a heuristic, and a wrong tap cannot corrupt
    anything — the reader that follows either finds exactly one editable field or refuses.
    """
    try:
        root = ElementTree.fromstring(device.dump_ui())
    except (RuntimeError, ElementTree.ParseError):
        return False
    candidates = []
    for node in _nodes(root):
        if (node.get("text") or "") != text:
            continue
        box = _bounds(node)
        if box is None or box[3] <= box[1] or box[2] <= box[0]:
            continue
        candidates.append(box)
    if not candidates:
        return False
    if lowest:
        candidates.sort(key=lambda box: box[1])
        box = candidates[-1]
    else:
        box = candidates[0]
    device.tap((box[0] + box[2]) // 2, (box[1] + box[3]) // 2)
    return True


def open_rules_editor(device: Device) -> None:
    """Navigate to the user-rules editor (首页 → 过滤器 → 自定义规则).

    The editor is the only surface that carries the raw text. It is reached through the shipped UI, so
    nothing in production had to change; if a label moves, the navigation fails and the caller refuses
    instead of reading something else.

    A device double that knows where the field is can supply `open_rules_editor` itself, which keeps
    the reader's *decisions* testable without a UI: what is tested is what the reader accepts, and the
    acceptance rules are the same either way.
    """
    supplied = getattr(device, "open_rules_editor", None)
    if callable(supplied):
        supplied()
        return
    device.start_main_screen()
    if not _tap_node(device, FILTERS_TAB, lowest=True):
        raise RuntimeError(f"the {FILTERS_TAB!r} tab was not on screen; the rules editor was not reached")
    if not _tap_node(device, USER_RULES_ROW):
        raise RuntimeError(
            f"the {USER_RULES_ROW!r} row was not on screen; the rules editor was not reached"
        )


def _editable_nodes(root: ElementTree.Element) -> list[ElementTree.Element]:
    """Nodes that represent the editor's text field.

    uiautomator exposes a Compose text field as an `android.widget.EditText` node whose `text`
    attribute is the whole value. Only that class is accepted: a `TextView` elsewhere on the screen
    (the diagnostics label, a hint) is a different surface and must not be mistaken for the field.
    """
    found = []
    for node in _nodes(root):
        if (node.get("class") or "") != "android.widget.EditText":
            continue
        # An EditText carries a text attribute even when the field is empty; a node without one is not
        # the field's value and is not accepted as "empty".
        if "text" not in node.attrib:
            continue
        found.append(node)
    return found


def _raw_editable_text(xml: str) -> list[str]:
    """The **undecoded** source of the `text` attribute of every editable node, in document order.

    XML attribute-value normalisation turns a literal tab or carriage return into a space before any
    parser sees it, so the parsed value cannot reveal whether that happened. The raw markup can: a
    lossless serialiser writes `&#9;`/`&#13;`, a lossy one writes the character itself. This is the
    only way to tell the two apart, and it is one regex over one element at a time — matching each
    `<node …>` element's own `text` attribute, so an unrelated node's whitespace cannot be mistaken for
    the field's.
    """
    found = []
    for element in re.findall(r"<node\b[^>]*>", xml):
        if 'class="android.widget.EditText"' not in element:
            continue
        match = re.search(r'(?<![\w:-])text="([^"]*)"', element)
        if match:
            found.append(match.group(1))
    return found


def _normalisation_loss(raw_values: list[str]) -> str:
    """An explanation when the raw markup shows whitespace XML normalisation has already folded.

    A serialiser that escapes a tab as `&#9;` is lossless and its raw text contains no literal tab; one
    that emits a literal tab is not, and the parser has already turned it into a space by the time the
    value exists. So the raw source is the thing to look at, not the parsed value.
    """
    for raw in raw_values:
        if "\t" in raw or "\r" in raw or "\n" in raw:
            return (
                "the dump contains a literal tab, carriage return or newline inside the field's text "
                "attribute; XML attribute-value normalisation folds those into spaces, so the "
                "original whitespace cannot be recovered from this read"
            )
    return ""


def read_rules(device: Device, attempts: int = 4, source: str = "auto") -> dict:
    """Read the user rules **losslessly**, or report that they cannot be read.

    `source="editor"` is the lossless path. `source="debug"` is kept for diagnostics only and refuses
    the blank marker outright, because that marker cannot be told apart from an empty set. `source="auto"`
    uses the editor when the given device can reach it (the real `Device` can; a test double may not).

    A read that fails or is ambiguous returns `known: False` with `error`; the caller must then perform
    no writes at all. "Not found" and "cannot distinguish" are never reported as "empty" — that
    conflation is what let an earlier version overwrite rules nobody had backed up.
    """
    if source == "auto":
        source = "editor" if callable(getattr(device, "start_main_screen", None)) else "debug"
    if source == "debug":
        return _read_rules_from_debug_screen(device, attempts)
    return _read_rules_from_editor(device, attempts)


def _read_rules_from_editor(device: Device, attempts: int) -> dict:
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            open_rules_editor(device)
            xml = device.dump_ui()
            root = ElementTree.fromstring(xml)
        except (RuntimeError, ElementTree.ParseError) as error:
            last_error = f"{type(error).__name__}: {error}"
            device.back()
            continue
        fields = _editable_nodes(root)
        if len(fields) != 1:
            # Two editable fields could be either the rules field or something else; zero means the
            # editor did not open. Neither can be read as a rule set, and guessing is exactly the
            # failure mode this tool exists to remove.
            last_error = (
                f"the rules editor showed {len(fields)} editable field(s); "
                "exactly one is required to know which text is the rule set"
            )
            device.back()
            continue
        value = fields[0].get("text")
        if value is None:
            last_error = "the rules editor's field carried no text attribute"
            device.back()
            continue
        # A literal tab or CR in the attribute has already been folded into a space by the XML
        # parser; the text is then not the user's text, and restoring it would silently rewrite their
        # whitespace. That is the same class of loss as `"$(cat …)"` dropping trailing newlines, and
        # it gets the same answer: refuse rather than install an approximation.
        loss = _normalisation_loss(_raw_editable_text(xml))
        if loss:
            device.back()
            return {"known": False, "rules": None, "source": "editor", "raw_label_text": "",
                    "attempts": attempt, "error": loss}
        state = {
            "known": True,
            "rules": value,
            "source": "editor",
            "raw_label_text": "editor:" + (fields[0].get("bounds") or ""),
            "attempts": attempt,
        }
        # A second read must agree: a field that changes between two dumps is being edited or is not
        # stable, and a backup of a moving target is not a backup.
        try:
            xml_again = device.dump_ui()
            fields_again = _editable_nodes(ElementTree.fromstring(xml_again))
        except (RuntimeError, ElementTree.ParseError) as error:
            device.back()
            return {**state, "known": False, "rules": None,
                    "error": f"the second read failed: {type(error).__name__}: {error}"}
        if len(fields_again) != 1 or (fields_again[0].get("text") or "") != value:
            device.back()
            return {**state, "known": False, "rules": None,
                    "error": "the editor's text changed between two reads; it cannot be backed up"}
        device.back()
        return state
    return {"known": False, "rules": None, "source": "editor", "raw_label_text": "",
            "attempts": attempts, "error": last_error or "the rules editor was not reached"}


def _read_rules_from_debug_screen(device: Device, attempts: int) -> dict:
    device.start_debug_screen()
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            xml = device.dump_ui()
            root = ElementTree.fromstring(xml)
        except (RuntimeError, ElementTree.ParseError) as error:
            last_error = f"{type(error).__name__}: {error}"
        else:
            for text in _texts(root):
                if text.startswith(RULES_LABEL):
                    value = text[len(RULES_LABEL):]
                    if value == BLANK_MARKER:
                        # `ifBlank { "（空）" }` collapses three different sets into this one string.
                        # The previous revision called that empty and recorded `known: true`; the
                        # safety probe turned it into deleted rules. Refuse instead.
                        return {
                            "known": False, "rules": None, "source": "debug",
                            "marker_interpreted_as_blank": True,
                            "raw_label_text": text, "attempts": attempt,
                            "error": (
                                "the debug screen shows the blank marker, which stands for an empty "
                                "set, a whitespace-only set and a set that literally is "
                                f"{BLANK_MARKER!r}; they cannot be told apart here, so nothing is captured"
                            ),
                        }
                    return {
                        "known": True, "rules": value, "source": "debug",
                        "marker_interpreted_as_blank": False,
                        "raw_label_text": text, "attempts": attempt,
                    }
            last_error = f"the debug screen carried no {RULES_LABEL!r} label"
        # Scroll down a little and try again; the block is below the fold.
        device.shell("input swipe 540 1600 540 600 300")
        time.sleep(1.0)
    return {"known": False, "rules": None, "source": "debug", "marker_interpreted_as_blank": False,
            "raw_label_text": "", "attempts": attempts, "error": last_error}


def _run_device_script(device: Device, script: str) -> tuple[int, str]:
    """Run one device-side script, transported base64-encoded. Returns `(status, output)`.

    The same technique the lock uses, and for the same reason: an inline command is re-parsed by the
    device's `sh`, and rule text contains `$`, `|`, `*`, `(`, quotes and newlines. Base64 has no quoting
    rules to get wrong.
    """
    import base64

    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    result = subprocess.run(
        ["adb", "-s", device.serial, "shell", f"echo {encoded} | base64 -d | sh 2>&1"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    return result.returncode, (result.stdout + result.stderr).replace("\r", "")


def set_rules(device: Device, rules: str) -> None:
    """Install `rules` through the app's own `DEBUG_SET_RULES` seam, byte for byte.

    Two independent losses have to be avoided, and the previous version suffered the second:

    * `adb shell` re-parses its argument through the device's `sh`, which expands `$removeparam` to
      nothing and splits on `|`/`*`/`(`, so the text goes over as a **file**;
    * `"$(cat FILE)"` drops **every trailing newline**, so the file is read with a one-character
      sentinel appended and that character removed afterwards — `V=$(cat f && printf X); V=${V%X}`.
      Without it a rule set ending in two newlines is installed with none: a silent edit of the user's
      text, and the review named it.
    """
    payload = Path(f".effectiveness/results/rules-restore-{os.getpid()}.txt")
    payload.parent.mkdir(parents=True, exist_ok=True)
    payload.write_bytes(rules.encode("utf-8"))
    push = subprocess.run(
        ["adb", "-s", device.serial, "push", str(payload), REMOTE_RULES],
        capture_output=True, text=True, check=False,
    )
    if push.returncode != 0:
        raise RuntimeError(f"could not push the rule set: {push.stderr.strip()[:200]}")
    # `wc -c < FILE` so the filename never lands in the output; the two counts are compared as strings
    # after trimming, because toybox pads them with spaces.
    script = (
        f"F='{REMOTE_RULES}'\n"
        "if [ ! -f \"$F\" ]; then echo 'RULE_STAGE_MISSING'; exit 3; fi\n"
        "V=$(cat \"$F\" && printf 'X')\n"
        "V=${V%X}\n"
        "LOCAL=$(wc -c < \"$F\" | tr -d ' ')\n"
        "GOT=$(printf '%s' \"$V\" | wc -c | tr -d ' ')\n"
        "if [ \"$LOCAL\" != \"$GOT\" ]; then\n"
        "  echo \"RULE_ROUNDTRIP_MISMATCH local=$LOCAL got=$GOT\"\n"
        "  exit 3\n"
        "fi\n"
        f"am broadcast -a {device.package}.action.DEBUG_SET_RULES "
        f"-n {device.package}/.filters.DebugCommandReceiver --es rules \"$V\" 2>&1\n"
    )
    status, out = _run_device_script(device, script)
    if "RULE_STAGE_MISSING" in out:
        raise RuntimeError("the staged rule file did not reach the device")
    if "RULE_ROUNDTRIP_MISMATCH" in out:
        raise RuntimeError(f"the rule text changed in transit: {out.strip()[:200]}")
    if "Broadcast completed" not in out:
        raise RuntimeError(f"the rule broadcast did not complete ({status}): {out.strip()[:200]}")
    # The device no longer needs the staged copy; leaving it behind leaks the user's rules into
    # `/data/local/tmp` for the next task to read.
    device.shell(f"rm -f {REMOTE_RULES}")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def capture(arguments: argparse.Namespace) -> int:
    device = Device(arguments.serial, arguments.package)
    try:
        state = read_rules(device, source=arguments.source_kind)
    except (RuntimeError, OSError) as error:
        say(f"rules: capture FAILED — {error}")
        return 2
    if not state.get("known"):
        # The caller must not proceed: installing a rule now would overwrite rules nobody recorded.
        say(f"rules: capture FAILED — {state.get('error') or 'the label was not found'}")
        say("rules: no rule write will be performed; nothing on the device was changed")
        return 2
    rules = state["rules"]
    record = {
        "captured_at": time.time(),
        "serial": arguments.serial,
        "package": arguments.package,
        "known": True,
        "source": state.get("source", "editor"),
        "rules": rules,
        "rules_len": len(rules),
        "rules_bytes": len(rules.encode("utf-8")),
        "rules_lines": rules.count("\n") + (1 if rules else 0),
        "trailing_newlines": len(rules) - len(rules.rstrip("\n")),
        "sha256": _digest(rules),
        "raw_label_text": state.get("raw_label_text", ""),
    }
    out = Path(arguments.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    marker = ""
    if rules.strip() == "":
        marker = " (blank rule set)" if rules else " (empty rule set)"
    if rules == BLANK_MARKER:
        marker = f" (literally {BLANK_MARKER!r}, which the debug screen cannot show either)"
    say(
        f"rules: captured {record['rules_len']} char(s) / {record['rules_bytes']} byte(s) / "
        f"{record['rules_lines']} line(s), {record['trailing_newlines']} trailing newline(s) "
        f"from the {record['source']} surface to {out}{marker}"
    )
    return 0


def restore(arguments: argparse.Namespace) -> int:
    path = Path(arguments.source)
    if not path.exists():
        say(f"rules: restore REFUSED — {path} does not exist; nothing was changed")
        return 2
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        say(f"rules: restore REFUSED — {path} is not a readable backup ({error}); nothing was changed")
        return 2
    if not record.get("known") or record.get("rules") is None:
        # A backup that could not read the rules must never be "restored" by clearing them: that
        # deletes a set this run never saw.
        say(f"rules: restore REFUSED — {path} records no readable rule set; nothing was changed")
        return 2
    if record.get("source") == "debug":
        say(
            "rules: restore REFUSED — that backup was taken from the diagnostics screen, which cannot "
            "distinguish an empty set from a literal （空）; only an editor backup is lossless"
        )
        return 2
    rules = record["rules"]
    if _digest(rules) != record.get("sha256"):
        say(
            "rules: restore REFUSED — the backup's sha256 does not match its text; it was edited or "
            "truncated after capture"
        )
        return 2

    device = Device(arguments.serial, arguments.package)
    try:
        set_rules(device, rules)
    except (RuntimeError, OSError) as error:
        say(f"rules: restore FAILED — {error}")
        say(f"rules: {path} is unchanged and still holds the original rule set")
        return 2
    # Verify by re-reading the same lossless surface, comparing the exact text — trailing newlines,
    # entities, quotes, `$`, backslashes and line breaks included. "The log says restored" is not an
    # observation; this is.
    observed = read_rules(device, source=arguments.source_kind)
    if not observed.get("known"):
        say(f"rules: restore UNVERIFIED — the editor could not be re-read ({observed.get('error')})")
        say(f"rules: {path} is unchanged and still holds the original rule set")
        return 2
    if observed["rules"] != rules:
        say(
            "rules: restore MISMATCH — the editor now holds "
            f"{len(observed['rules'])} char(s), the backup held {len(rules)}; the backup at {path} is "
            "unchanged"
        )
        if observed["rules"].rstrip("\n") == rules.rstrip("\n"):
            say("rules:   the only difference is the number of trailing newlines")
        return 2
    say(f"rules: restored and verified byte for byte ({len(rules)} char(s), {len(rules.encode('utf-8'))} byte(s))")
    return 0


def install(arguments: argparse.Namespace) -> int:
    """Install the rule text in a file, byte for byte, without pretending it is a restore.

    This is the path the acceptance transaction uses for its *own* probe rules. It exists as a
    subcommand rather than a fourth copy of the push-and-broadcast sequence because the trailing-newline
    and shell-quoting handling has to be the same code in both directions: one place that gets it wrong
    is one place to fix, and the file's last line is part of the rule set.
    """
    path = Path(arguments.source)
    if not path.is_file():
        say(f"rules: install REFUSED — {path} does not exist")
        return 2
    rules = path.read_bytes().decode("utf-8")
    device = Device(arguments.serial, arguments.package)
    try:
        set_rules(device, rules)
    except (RuntimeError, OSError) as error:
        say(f"rules: install FAILED — {error}")
        return 2
    say(f"rules: installed {len(rules)} char(s) / {len(rules.encode('utf-8'))} byte(s)")
    return 0


def show(arguments: argparse.Namespace) -> int:
    record = json.loads(Path(arguments.source).read_text(encoding="utf-8"))
    say(
        f"known={record.get('known')} source={record.get('source')} len={record.get('rules_len')} "
        f"bytes={record.get('rules_bytes')} lines={record.get('rules_lines')} "
        f"trailing_newlines={record.get('trailing_newlines')} sha256={record.get('sha256')}"
    )
    if record.get("known") and record.get("rules") is not None:
        say("--- rules (repr, so trailing whitespace is visible) ---")
        say(repr(record["rules"]))
        say("--- end ---")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture", "restore", "install", "show"))
    parser.add_argument("--out", default="", help="capture: file to write")
    parser.add_argument("--from", dest="source", default="", help="restore/show: file to read")
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument(
        "--source", dest="source_kind", default="auto", choices=("auto", "editor", "debug"),
        help="where to read the rules: the editor (lossless, default), the diagnostics screen "
             "(refuses the blank marker), or auto",
    )
    arguments = parser.parse_args(argv)
    # `show` reads a file that is already on this machine and prints it; it must keep working with no
    # phone attached and no adb on PATH (it is the command an operator uses *to inspect* a backup
    # before deciding whether to restore it). Every other command drives the device, so the serial is
    # resolved only for those — and only after the argument checks below, so a missing `--out`/`--from`
    # is reported as that, not as a device problem.
    if arguments.command == "capture":
        if not arguments.out:
            say("capture needs --out")
            return 2
        arguments.serial = device_serial.serial_from(arguments)
        return capture(arguments)
    if not arguments.source:
        say(f"{arguments.command} needs --from")
        return 2
    if arguments.command == "show":
        return show(arguments)
    arguments.serial = device_serial.serial_from(arguments)
    if arguments.command == "restore":
        return restore(arguments)
    return install(arguments)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
