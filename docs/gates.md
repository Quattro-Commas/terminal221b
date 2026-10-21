# Gates: the exit-code contract, and which copy is canonical

These gates exist because a gate that reports green without verifying anything is
indistinguishable, in a log, from a gate that passed. Everything below is in
service of one rule:

> **A gate that cannot enumerate its subjects must not report 0.**

Absence of evidence is not evidence of absence, and the two produce the same line.

## The contract

| Exit | Meaning |
|---|---|
| `0` | clean — every subject was examined, nothing was found |
| `1` | findings — a subject was examined and it is wrong |
| `2` | inconclusive — a subject could not be read, or there was none to read |

A gate that returns 2 for everything satisfies "never falsely passes" and is
useless, so the contract is not one-sided: a clean subject must give 0 and a
subject with a real problem must give 1. All three are checked, by
`check-gates-are-honest.sh`, which **drives** each gate against three fixtures
rather than reading it — reading a gate cannot tell you what it does when it is
given nothing.

## The canonical copies

These files are **copied** into every repository that uses them, not shared. A
submodule or a package would put a checkout step in front of the gate that runs
the gate, which is a dependency in the wrong direction. The checksums are what
keep the copies honest: a divergence shows up as a checksum that no longer
matches, not as a silent behaviour change in one repository.

| File | md5 | Lines |
|---|---|---|
| `scripts/check-home-paths.sh` | `09997aab74a0403710d5bfa0e7cfd495` | 271 |
| `scripts/check-workflows-can-fail.sh` | `631ef2b98019f609062def0f1ed7d58a` | 355 |
| `scripts/check-gates-are-honest.sh` | `1bc58cf2417e55833bd8be54fff6d565` | 979 |
| `scripts/verify-gates.sh` | `a24889538e2ba985d2527597c1bdd399` | 97 |

`.gate-manifest` is deliberately **not** in that table. It names the gates of the
repository it sits in and declares that repository's entry point, so it is
different in every repository by design — four of them share a checksum today and
`verification-skills` has its own, because its entry point is a Makefile and it
registers a second gate. A canonical checksum for it would be a canonical file
that is not canonical.

A repository carries only the subset it uses. `verification-skills` has no
`check-workflows-can-fail.sh` and no `verify-gates.sh`: its entry point is a
Makefile, and `verify-gates.sh` would be a second entry point that CI does not
call. The table lists the family, not one repository's `scripts/` directory.

To check a copy:

```bash
md5sum scripts/check-home-paths.sh scripts/check-workflows-can-fail.sh \
       scripts/check-gates-are-honest.sh scripts/verify-gates.sh
```

`check-gates-are-honest.sh` also checks this table — the checksum *and* the line
count of every file it names, and reports a row this repository does not carry as
absent rather than wrong. It is inside the auditor rather than a script of its own
because a separate script would be a gate the manifest does not name and the
runner does not list, which is the thing the auditor exists to forbid.

## Running them

One entry point, and it is the same one CI calls:

```bash
./scripts/verify-gates.sh
```

Self-tests run before audits, always. An audit performed by an instrument that
cannot fail proves nothing about the tree, so the instruments are checked before
a reading from them is believed.

## What the controls are for

`check-home-paths.sh` 10 controls, `check-workflows-can-fail.sh` 14,
`check-gates-are-honest.sh` 20 — **44 in total, 32 of which assert a refusal.**

That asymmetry is the point. A control set that only ever proves the happy path
is a decorator, not a gate. Every gate's self-test includes a control that
reproduces the defect the gate exists to catch, and each fix in this history was
verified by removing the guard and watching a control go red before restoring it.

The meta-gate's own controls were the last ones repaired, and they are the
clearest case of a control that was green without testing anything. One of them,
`refuses-a-run-but-unregistered-gate`, was passing because the *previous* control
had left its gate in the runner array — and an unregistered gate is exactly what
that leftover produces. Isolated on a clean baseline it returned 0. Another,
`refuses-a-missing-gate`, asserted only an exit code, and that code was available
for the wrong reason: running a script that does not exist yields 127, the
verdict check rejects 127, and the audit exits 1 whether or not the presence
check exists — so deleting the presence check left the control green, and the
finding it produced described a gate that ran and misbehaved rather than one that
is not installed. Both now assert what they claim to, and both are proven
load-bearing by removing the guard and watching them go red.

A control that cannot fail is a gate that cannot fail, which is the whole problem
one level up.

## Auditing a gate that finds its own root

Two of the subject kinds needed more than a path argument.

A gate like elohim's `verify_skill_roots.py` resolves its repository from
`Path(__file__).parent.parent`. Given a fixture path it ignores the argument,
audits the real repository, and answers 0 — a clean verdict about a tree it never
looked at, which is the exact failure this file exists to refuse. So there is a
third invocation mode:

    <subject-kind> <invocation> <argv…>

    path        the fixture is appended as the last argument (default)
    cwd         the gate runs with its working directory set to the fixture
    relocated   the gate is copied into the fixture and run from there

`relocated` is the one that matters, and it has a limit worth stating: the gate's
own dependencies are its problem. A gate that imports a sibling module cannot be
relocated without it, and finding that out here is better than finding it out in a
CI log.

The `skill-tree` kind exists alongside it. Its subject is a `skills/` directory of
`SKILL.md` files rather than a work tree, and its unlookable fixture is a
directory that **exists and holds nothing** — not an absent one, because a gate
that handles "no directory" but not "directory with nothing in it" is the common
half-finished case and the fixture has to be able to tell those apart.

Its five controls include the defect measured in miniature in elohim: a skill gate
right about a real finding, right about a good skill, and answering 0 when it has
no skills to look at. Making that fixture honest turns the control red, which is
what makes the control worth having — during this work four of the five were
briefly green because their fixture directory was never created, and the gate was
absent rather than blind.

The defect that recurred most often, and is the reason `check-gates-are-honest.sh`
exists at all: a gate pointed at an empty repository, a directory that is not a
work tree, or a path that does not exist, reported a clean tree it had never
scanned. The third revision of `check-home-paths.sh` (126 lines) and the partial
one (134 lines) both did this. Only the canonical 271-line file returns 2.

## Two things about these files that are not obvious

**No literal home directory appears in any of them, ever** — not in a fixture, not
in a comment. `check-home-paths.sh` scans its own source, so a literal is a
self-inflicted finding. Fixtures build a real path from `$HOME` at runtime. This
has caught a hardcoded path in a first draft of the meta-gate, on the same commit
it was written.

**Workflow files are line-walked, not parsed as YAML.** None of these
repositories depends on PyYAML, and adding a dependency to a gate that exists
because the gates were not trusted is the wrong trade. The consequence is a known
limit: the parser assumes the indentation these files already use, and it will
reject a workflow that indents differently rather than mis-read it.
