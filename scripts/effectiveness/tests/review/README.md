# The reviewer's own reproductions (verbatim)

`review_stage2_harness.py` and `review_stage2_r2.py` are the two scripts the tech lead attached to the
parent issue (MYS-2786) to demonstrate, independently of this repository's own tests, that the I2
acceptance harness accepted invalid input. They are copied here **unmodified** so
`test_review_scripts.py` can run them on every change: the stage-3 acceptance criterion names both by
name, and a harness that only satisfies its own tests has not been checked by anyone else.

`review_stage3.py` is the same kind of script for the stage-3 harness (concurrency group total, snapshot
metadata, lock-before-write).

They expect a checkout of this repository next to them (`./zshield-android`), which is what the test
files stage in a scratch directory. All three exit 0 against the current tree; the same test files also
break the tools deliberately and require them to exit non-zero, so "they pass" cannot mean "they stopped
checking".

## `review_device_condition.py` (MYS-2820, first acceptance)

The probe attached to the first acceptance of MYS-2820. It runs `condition.sh` itself — not the
libraries under it — against `test_acceptance_entry.StubDevice`, and reported:

```text
no_lock_cleanup:        exit=0; attempted_rule_write=True;  original_preserved=True
failed_backup_install:  exit=0; attempted_rule_write=True;  original_preserved=False
exit_trap_return_failure: process_exit=0 (expected nonzero)
```

`condition-probes-before.log` is that run, and the two `condition-*-before.log` files are the runs'
own output. They are kept byte-identical (`test_condition_entry.py` asserts it) because the round is
measured against them.

Again, notes on running it that are facts about the script:

* **Its third line is a standalone `bash -c` snippet**, not code from this repository — it demonstrates
  that `return` from an EXIT trap does not set the exit status. That is still true, and the snippet
  still prints 0; what changed is that `condition.sh`, `pss_idle.sh` and `tunnel_acceptance.sh` no
  longer use that construct (they `exit "$accumulated"` from a disarmed trap). `ExitStatusTest` pins
  both the premise and the fix.
* **It imports `test_acceptance_entry`**, so a staged tree needs the repository's `tests` directory on
  `PYTHONPATH` — which `test_condition_entry.py` supplies.
* Its `original_preserved` for `no_lock_cleanup` was already `True`; the defect there was that a
  *write was attempted at all* under another task's lock. Both columns matter.

## `review_stage3_safety.py` (MYS-2820, first delivery)


The probe attached to MYS-2820. It reproduced three defects in the revision it was written against;
`stage3-r2-safety-before.log` is that run, byte for byte:

```text
active_canonical_lock: take_exit=0; canonical_unchanged=True; accepted=True
stale_takeover_interleaving: A_exit=0; B_exit=0; both_acquired=True; final_meta='…token=B…'
literal_marker_backup: original='（空）'; known=True; stored=''; lossy=True
```

It is kept here **byte-identical** to the attachment (`test_review_stage3_safety.py` asserts that with
`cmp`-style equality, so an edit is a test failure rather than a quiet divergence).

Two notes on running it today, both recorded because they are facts about the script rather than about
the code under test:

* **It has no failure counter.** It prints three lines and exits 0 either way; the verdicts in those
  lines are the contract, and the tests assert them.
* **Its `lossy=` term is `state['rules'] != '（空）'`**, so a capture that correctly *refuses* also prints
  `lossy=True`. `known=False; stored=None` is the success condition for that case, and the tests assert
  those fields.
* **Its final print for case 2 reads `lock/meta`**, the previous revision's internal layout. The lock is
  now the canonical **file** `AGENTS.md` specifies, so that one line raises `NotADirectoryError` after
  the case's verdict has already been computed. `test_review_stage3_safety.py` runs the attachment
  unmodified for cases 1 and 3, drives case 2 itself with the probe's own barrier on the rename, and
  separately runs a copy whose *only* change is that diagnostic line so the whole script completes.
