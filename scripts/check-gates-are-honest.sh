#!/usr/bin/env bash
# Refuse a gate that reports a clean pass when it could not look at anything.
#
# The other gates in this repository check the repository. This one checks the
# gates, and it does so by driving them rather than by reading them, because
# reading a gate cannot tell you what it does when it is given nothing. A gate
# that reports "clean" for a repository it never scanned produces a line in a CI
# log that is indistinguishable from a gate that passed, and that is the most
# expensive kind of bug: nothing in a diff says so.
#
# The check is *differentiation*, not merely "did not exit 0". Each registered
# gate is driven against three fixtures and has to be distinguished across all
# three:
#
#   clean        exit 0   every subject was read, nothing found
#   dirty        exit 1   a subject was read and it is wrong
#   unlookable   exit 2   a subject could not be read, or there was none
#
# Requiring all three is what stops the cheap fix from being "always exit 2". A
# gate that returns 2 for everything satisfies "never reports a false green" and
# is useless; the clean fixture rejects it. A gate that returns 0 for everything
# is the bug this file exists to find; the unlookable fixture rejects it.
#
# Gates register in `.gate-manifest`, one line each:
#
#   <subject-kind> <gate-command>
#
# The subject kind selects a fixture builder. An unknown kind is a finding, not
# something to skip: it forces whoever adds a gate to answer "what does this look
# at, and what does it look like when there is nothing?", which is the question
# this file exists to make unavoidable.
#
# Usage:
#   check-gates-are-honest.sh [repo-dir]   audit the registered gates
#   check-gates-are-honest.sh --self-test prove the audit can both fail and pass
set -uo pipefail

MANIFEST_NAME='.gate-manifest'
META_NAME='check-gates-are-honest.sh'

# What each subject kind must look like in each of the three states. A builder
# writes the left column; this table is the contract those columns are held to.
#
# Built at runtime, never written out: this file is tracked and is itself scanned
# by check-home-paths.sh, so a literal path here would make that gate fail on
# this file's own canary.
real_home() { (cd ~ && pwd); }

# Assembled at runtime, for the reason above: a literal here would be a finding
# in this repository's own tree. The secret needs twelve or more characters after
# the assignment, because that is what the identifier gate's pattern requires --
# a shorter canary would not match and the fixture would pass for the wrong
# reason.
synthetic_secret() { printf 's3cret-value-%s' "$(id -u)0000"; }
synthetic_mail() { printf 'someone@%s.%s' 'corpmail' 'io'; }
synthetic_hostroot() { printf '/%s' 'opt'; }

fixture_clean_git_tree() {
  local d="$1"
  mkdir -p "$d"
  ( cd "$d" && git init -q . && printf 'nothing here\n' > clean.txt && git add clean.txt )
}

# The dirty fixture carries one defect from EVERY class a leak gate might own,
# not just one. Two gates can share the `git-tree` kind and still disagree about
# what a finding looks like: the home-path gate reads /home/<someone>, and the
# identifier gate does not look there at all. A fixture holding only a home path
# therefore satisfies the first and reports 0 for the second, and the meta-gate
# would refuse a gate that is behaving correctly.
#
# The meta-gate is asserting the *contract* -- clean, finding, unlookable -- and
# not the gate's coverage. Coverage is the gate's own self-test's job, and both
# of these gates already carry controls proving they catch their own classes. So
# the fixture plants one of each, and any leak gate has something in its own
# class to find. Every value is assembled at runtime: this file is tracked, and
# both gates scan their own source.
fixture_dirty_git_tree() {
  local d="$1"
  mkdir -p "$d"
  (
    cd "$d" || return 1
    git init -q .
    {
      printf 'weights at %s/models\n' "$(real_home)"
      printf 'api_key = "%s"\n' "$(synthetic_secret)"
      printf 'contact: %s\n' "$(synthetic_mail)"
      printf 'cached under %s/llama\n' "$(synthetic_hostroot)"
    } > leak.txt
    git add leak.txt
  )
}

fixture_unlookable_git_tree() {
  local d="$1"
  mkdir -p "$d"
  ( cd "$d" && git init -q . )
}

# A sound workflow: a job with a real step that can fail.
_workflow_sound() {
  cat <<'YAML'
name: Gates
on:
  push:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - run: ./scripts/run-something-real
YAML
}

# A workflow whose only job fetches the code and does nothing with it.
_workflow_vacuous() {
  cat <<'YAML'
name: Gates
on:
  push:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
YAML
}

fixture_clean_workflow_dir() {
  local d="$1"
  mkdir -p "$d/.github/workflows"
  _workflow_sound > "$d/.github/workflows/w.yml"
}

fixture_dirty_workflow_dir() {
  local d="$1"
  mkdir -p "$d/.github/workflows"
  _workflow_vacuous > "$d/.github/workflows/w.yml"
}

fixture_unlookable_workflow_dir() {
  # No .github/workflows at all. This is the shape the whole effort exists to
  # catch: a repository with no CI is not a repository that is fine.
  mkdir -p "$1"
}

# Run a gate against one fixture and echo its exit code. The gate's own stdout
# and stderr are discarded: this file judges the exit code, and printing a
# gate's findings here would be reporting a second opinion it never asked for.
run_gate() {
  local gate="$1" dir="$2" mode="${3:-path}"
  case "$mode" in
    path)
      "$gate" "$dir" >/dev/null 2>&1 ;;
    cwd)
      # The fixture is appended to the manifest's argv, not injected as an
      # argument here, so this only changes where the gate is standing.
      ( cd "$dir" && "$gate" ) >/dev/null 2>&1 ;;
    relocated)
      # A gate that resolves its own repository from its own path cannot be
      # pointed at a fixture with an argument -- it would go on auditing the real
      # repository and answer 0 for a tree it never looked at, which is the exact
      # false green this file exists to refuse. So it is copied into the fixture
      # and run from there, and `dir` stands in for the repository it will
      # resolve. The gate's own dependencies are its problem: a gate that needs a
      # sibling module cannot be relocated without it, and finding that out here
      # is better than finding it out in a CI log.
      ( mkdir -p "$dir/tools" && cp "$gate" "$dir/tools/$(basename "$gate")" \
        && cd "$dir" && python3 "tools/$(basename "$gate")" ) >/dev/null 2>&1 ;;
    *)
      echo "unknown invocation mode: $mode" >&2; return 127 ;;
  esac
  echo $?
}

# Echo the three fixture builders for a kind, or nothing if the kind is unknown.
# A skill tree: a `skills/` directory holding SKILL.md files. Separate from
# git-tree because the subject is the skills, not the work tree, and because the
# empty case is a directory that exists and holds nothing -- which is the case a
# skill gate is most likely to answer "clean" to.
#
# The three states, and the unlookable one is the point:
#   clean        one well-formed skill
#   dirty        one skill a loader would reject
#   unlookable   skills/ present and empty: no SKILL.md anywhere
#
# A gate that roots itself at its own location (`Path(__file__).parent.parent`)
# cannot be driven with a path argument at all, so this kind is only usable with
# the `relocated` invocation. That is the whole reason that mode exists.
_well_formed_skill() {
  cat <<'MD'
---
name: well-formed
description: Use when a gate needs one skill a loader would accept, nothing else.
license: MIT
---

# Well formed

A body that is long enough to be a real skill and carries nothing a loader
would object to.
MD
}

fixture_clean_skill_tree() {
  local d="$1"
  mkdir -p "$d/skills/well-formed"
  _well_formed_skill > "$d/skills/well-formed/SKILL.md"
}

fixture_dirty_skill_tree() {
  local d="$1"
  # One defect of each class a skill gate might own, for the same reason the
  # git-tree dirty fixture carries a home path, a secret and a host path: two
  # gates can share this kind and still disagree about what a finding is. The
  # frontmatter gate looks at the *content* of a SKILL.md; the roots gate looks
  # at whether one *name* is reachable from two roots. A fixture holding only a
  # malformed skill satisfies the first and reports 0 for the second, and the
  # auditor would refuse a gate that is behaving correctly.
  #
  # The duplicated name is planted under two roots the roots gate actually
  # inspects, not under arbitrary directories, so the fixture is a real
  # duplicate for a gate configured the way this repository configures it.
  mkdir -p "$d/skills/alpha" "$d/plugins/elohim/skills/alpha" "$d/skills/broken"
  _well_formed_skill > "$d/skills/alpha/SKILL.md"
  _well_formed_skill > "$d/plugins/elohim/skills/alpha/SKILL.md"
  # No frontmatter block at all: the defect every SKILL.md loader refuses, and
  # one that needs no pattern knowledge to construct.
  printf '# Broken\n\nA skill with no frontmatter block at all.\n' \
    > "$d/skills/broken/SKILL.md"
}

fixture_unlookable_skill_tree() {
  local d="$1"
  # Present and empty. Not absent: a gate that handles "no directory" but not
  # "directory with nothing in it" is the common half-finished case, and the
  # fixture has to be able to tell the two apart to catch it.
  mkdir -p "$d/skills"
}

builders_for() {
  case "$1" in
    git-tree)
      echo "fixture_clean_git_tree fixture_dirty_git_tree fixture_unlookable_git_tree" ;;
    workflow-dir)
      echo "fixture_clean_workflow_dir fixture_dirty_workflow_dir fixture_unlookable_workflow_dir" ;;
    skill-tree)
      echo "fixture_clean_skill_tree fixture_dirty_skill_tree fixture_unlookable_skill_tree" ;;
    *) return 1 ;;
  esac
}

# Explain one observed triple. Kept separate from the comparison so the report
# says what was wrong rather than only that something was.
verdict() {
  local name="$1" c="$2" d="$3" u="$4"
  if [ "$c" -eq 0 ] && [ "$d" -eq 1 ] && [ "$u" -eq 2 ]; then
    return 0
  fi
  if [ "$u" -ne 2 ]; then
    printf '%s: given a subject it cannot look at, it reported exit %s, not 2 -- this gate can report a clean pass having verified nothing\n' \
      "$name" "$u"
  fi
  if [ "$c" -ne 0 ]; then
    printf '%s: given a clean subject it reported exit %s, not 0 -- it refuses a tree that is fine\n' \
      "$name" "$c"
  fi
  if [ "$d" -ne 1 ]; then
    printf '%s: given a subject with a real problem it reported exit %s, not 1 -- it cannot tell a finding from a pass\n' \
      "$name" "$d"
  fi
  return 1
}

audit() {
  local dir="${1:-.}" manifest="$1/.gate-manifest"
  manifest="$dir/$MANIFEST_NAME"
  local tmp status problems=0 checked=0
  local -a findings=() gates=()
  # Where the gates are meant to be run from, and what CI is meant to call. A
  # repository whose entry point is a Makefile is not a repository with a broken
  # entry point, so the wiring check reads these from the manifest rather than
  # hard-coding one repository's shape.
  local runner_rel='scripts/verify-gates.sh'
  local ci_entry_rel='.github/workflows/gates.yml'
  local ci_command='./scripts/verify-gates.sh'
  local mline
  while IFS= read -r mline || [ -n "$mline" ]; do
    case "$mline" in
      '# runner:'*)
        runner_rel="${mline#*runner:}"; runner_rel="${runner_rel%%#*}"
        runner_rel="${runner_rel#"${runner_rel%%[![:space:]]*}"}" ;;
      '# ci-entry:'*)
        ci_entry_rel="${mline#*ci-entry:}"; ci_entry_rel="${ci_entry_rel%%#*}"
        ci_entry_rel="${ci_entry_rel#"${ci_entry_rel%%[![:space:]]*}"}" ;;
      '# ci-command:'*)
        ci_command="${mline#*ci-command:}"; ci_command="${ci_command%%#*}"
        ci_command="${ci_command#"${ci_command%%[![:space:]]*}"}" ;;
    esac
  done < "$manifest"

  if [ ! -f "$manifest" ]; then
    echo "$dir: inconclusive -- no $MANIFEST_NAME, so no gate is registered and" \
      "none was audited" >&2
    return 2
  fi
  if [ ! -d "$dir/scripts" ]; then
    echo "$dir: inconclusive -- no scripts directory to find the gates in" >&2
    return 2
  fi

  tmp="$(mktemp -d)"
  # Double-quoted on purpose. A single-quoted RETURN trap body is expanded when
  # the trap fires, and a RETURN trap is a single global slot that any function
  # may overwrite -- so it can fire at a *caller's* return, where `$tmp` is that
  # caller's directory. Interpolating now means this trap can only ever remove
  # the directory this function created.
  trap "rm -rf '$tmp'" RETURN

  local line kind gate builders cb db ub base c d u
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in ''|'#'*) continue ;; esac
    # <subject-kind> [invocation] <argv…>, and the invocation is optional so the
    # two-column form that predates it keeps working: with one word left it is
    # the command, and the invocation is the historical `path`. Word-splitting
    # rather than substring cuts, so an extra space in a hand-edited manifest does
    # not turn the invocation into part of the path.
    # shellcheck disable=SC2086
    set -- $line
    kind="$1"; shift
    invocation="path"
    if [ "$#" -gt 1 ]; then
      invocation="$1"; shift
    fi
    gate="$*"
    [ -n "$gate" ] || continue
    checked=$((checked + 1))
    gates+=("$gate")

    if ! builders="$(builders_for "$kind")"; then
      findings+=("$gate: subject kind '$kind' has no fixture builder -- a gate whose subject cannot be made empty has not been audited")
      problems=$((problems + 1))
      continue
    fi
    if [ ! -x "$dir/$gate" ]; then
      findings+=("$gate: registered in $MANIFEST_NAME but not present and executable at that path")
      problems=$((problems + 1))
      continue
    fi

    set -- $builders
    cb="$1"; db="$2"; ub="$3"
    base="$tmp/$(printf '%s' "$gate" | tr -c 'A-Za-z0-9._-' '_')"
    "$cb" "$base/clean"
    "$db" "$base/dirty"
    "$ub" "$base/unlookable"

    c="$(run_gate "$dir/$gate" "$base/clean" "$invocation")"
    d="$(run_gate "$dir/$gate" "$base/dirty" "$invocation")"
    u="$(run_gate "$dir/$gate" "$base/unlookable" "$invocation")"

    if ! verdict "$gate" "$c" "$d" "$u"; then
      problems=$((problems + 1))
      findings+=("$(verdict "$gate" "$c" "$d" "$u" 2>/dev/null | head -3)")
    fi
  done < "$manifest"

  # A gate that verify-gates.sh runs but that nobody registered here is being
  # executed with no audit of whether it can fail. The manifest is the only
  # record of which gates matter, so a gate that falls out of it while still
  # being run is a silent loss of exactly the thing this file exists to provide.
  local runner="$dir/$runner_rel"
  if [ ! -f "$runner" ]; then
    echo "$dir: inconclusive -- no $runner_rel, so nothing records which" \
      "gates are meant to run" >&2
    return 2
  fi
  if ! grep -q "$META_NAME --self-test" "$runner"; then
    findings+=("$runner_rel does not run this gate's self-test, so its judgement is never checked")
    problems=$((problems + 1))
  fi
  local entry
  for entry in "${gates[@]}"; do
    if ! grep -qF "$entry" "$runner"; then
      findings+=("$entry is registered here but $runner_rel never runs it")
      problems=$((problems + 1))
    fi
  done

  # The other direction, which is the one that actually bites. A gate can be
  # running in verify-gates.sh and still fall out of the manifest, and then
  # nothing has ever checked whether it can fail -- it is executed, and its
  # opinion is believed, and no one has asked whether that opinion means
  # anything. Reading the runner rather than the manifest is what catches it.
  #
  # This gate is exempt from the requirement: it is the auditor, and auditing
  # itself would be circular.
  local invoked_path
  while IFS= read -r invoked_path; do
    [ -n "$invoked_path" ] || continue
    [ "$invoked_path" = "scripts/$META_NAME" ] && continue
    if ! printf '%s\n' "${gates[@]}" | grep -qxF "$invoked_path"; then
      findings+=("$invoked_path is run by $runner_rel but is not registered in $MANIFEST_NAME, so nothing has checked whether it can fail")
      problems=$((problems + 1))
    fi
    # Read the array's entries, not every mention of a path in the file. The
    # header comment talks about this script by name, and a grep that counted
    # that would demand the runner be registered as a gate in itself.
  done <<< "$(grep -oE '^[[:space:]]*"scripts/[A-Za-z0-9._-]+\.sh' "$runner" \
             | grep -oE 'scripts/[A-Za-z0-9._-]+\.sh' | sort -u)"

  # And the entry point CI calls has to be the one that runs all of this.
  local wf="$dir/$ci_entry_rel"
  if [ ! -f "$wf" ]; then
    findings+=("no $ci_entry_rel, so nothing in CI runs any of this")
    problems=$((problems + 1))
  # Fixed-string, not a pattern. The command is whatever the manifest says it is:
  # a Makefile invocation has no "run:" prefix to anchor on, and a pattern that
  # assumed one would report a perfectly wired repository as unwired.
  elif ! grep -qF "$ci_command" "$wf"; then
    findings+=("$ci_entry_rel does not run '$ci_command', so the gates are not in CI")
    problems=$((problems + 1))
  fi

  # The table in docs/gates.md is what keeps the copies of these files honest
  # across repositories, so it is checked here rather than trusted. A stale
  # checksum in that document is the same failure as a diverged copy: both leave
  # a repository believing it matches when it does not. This lives inside the
  # auditor rather than in a script of its own, because a separate script would
  # be a gate the manifest does not name and the runner does not list -- which is
  # the exact thing the checks above exist to forbid.
  #
  # A row naming a file this repository does not carry is skipped rather than
  # failed. The table lists the family; a repository uses the subset it needs.
  local doc="$dir/docs/gates.md"
  if [ -f "$doc" ]; then
    local dline dfile dwant dlines dgot dhave
    while IFS= read -r dline; do
      case "$dline" in
        '| `scripts/'*) ;;
        *) continue ;;
      esac
      dfile=$(printf '%s' "$dline" | sed -n 's/^| `\([^`]*\)`.*/\1/p')
      dwant=$(printf '%s' "$dline" | sed -n 's/.*`\([0-9a-f]\{32\}\)`.*/\1/p')
      dlines=$(printf '%s' "$dline" | sed -n 's/.*| \([0-9][0-9]*\) *|$/\1/p')
      if [ -z "$dfile" ] || [ -z "$dwant" ]; then
        findings+=("docs/gates.md has a checksum row this gate cannot read: $dline")
        problems=$((problems + 1))
        continue
      fi
      [ -f "$dir/$dfile" ] || continue
      dgot=$(md5sum "$dir/$dfile" | cut -d' ' -f1)
      dhave=$(wc -l < "$dir/$dfile")
      if [ "$dgot" != "$dwant" ]; then
        findings+=("docs/gates.md records $dwant for $dfile, but this copy is $dgot -- the copies have diverged")
        problems=$((problems + 1))
      elif [ "$dhave" != "$dlines" ]; then
        # The md5 already pins the content, so a line count that disagrees means
        # the table was edited by hand and only the checksum was left correct.
        findings+=("docs/gates.md records $dlines lines for $dfile, but this copy has $dhave -- the table was edited by hand")
        problems=$((problems + 1))
      fi
    done < "$doc"
  fi

  if [ "$checked" -eq 0 ]; then
    echo "$dir: inconclusive -- $MANIFEST_NAME lists no gates, so none was audited" >&2
    return 2
  fi

  if [ "$problems" -ne 0 ]; then
    echo "$dir: ${problems} of ${checked} registered gate(s) are not honest about" \
      "what they verified:" >&2
    for f in "${findings[@]}"; do echo "  $f" >&2; done
    echo "" >&2
    echo "  A gate must distinguish: 0 clean, 1 findings, 2 inconclusive." >&2
    return 1
  fi
  echo "$dir: ${checked} registered gate(s), each distinguishing clean, findings and inconclusive"
  return 0
}

self_test() {
  local tmp status failures=0
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" RETURN

  # One synthetic repository, several gates of known honesty, and a manifest
  # naming them. The dishonest fixtures are the interesting half: a gate that
  # cannot tell "clean" from "could not look" must be reported, and the two that
  # are broken in the *opposite* directions must be reported too, or this file
  # would accept a gate that had been "fixed" by making it fail at everything.
  #
  # These are copies written into a temp directory, never references to the live
  # scripts, so the control keeps testing this file's judgement after the real
  # gates are fixed.
  local repo="$tmp/repo"
  mkdir -p "$repo/scripts"

  # Honest: distinguishes all three.
  cat > "$repo/scripts/honest-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
dir="${1:-.}"
[ -d "$dir" ] || exit 2
if [ -f "$dir/leak.txt" ]; then
  echo "found it" >&2
  exit 1
fi
[ -f "$dir/clean.txt" ] || exit 2
echo "clean"
GATE

  # Dishonest in the way that started all this: reports a pass for a tree it
  # never looked at.
  cat > "$repo/scripts/always-clean-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
exit 0
GATE

  # Dishonest in the opposite direction, and the one a careless fix produces.
  cat > "$repo/scripts/always-two-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
exit 2
GATE

  # The shape that actually shipped, in miniature: right about a real finding,
  # right about a clean tree, and silently wrong about everything it could not
  # read. This is the specific defect the whole effort is about, and it is worth
  # its own control rather than relying on the always-passes one above, because
  # that gate is wrong in every direction and this one is wrong in only the one
  # that looks like a pass in a CI log.
  cat > "$repo/scripts/fix-after-the-fact-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
dir="${1:-.}"
if [ -f "$dir/leak.txt" ]; then
  exit 1
fi
exit 0
GATE

  # Half-honest: gets the unlookable case right, calls everything else a finding.
  cat > "$repo/scripts/only-refuses-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
dir="${1:-.}"
[ -d "$dir" ] || exit 2
[ -f "$dir/clean.txt" ] || exit 1
exit 0
GATE

  chmod +x "$repo"/scripts/*.sh
  # The wiring check below looks for these, so a synthetic repo has to have them
  # or every control would be reporting the missing wiring instead of the gate
  # under test.
  mkdir -p "$repo/.github/workflows"
  # The real auditor, copied in rather than referenced. Every fixture's runner
  # names this gate, and a repository whose runner names a file that is not
  # there is wired to nothing -- so a control built on that would be asserting a
  # property the fixture does not actually have. The audit only greps the runner
  # for the name and never runs it, so this cannot recurse.
  cp "${BASH_SOURCE[0]}" "$repo/scripts/$META_NAME"
  chmod +x "$repo/scripts/$META_NAME"
  cat > "$repo/.github/workflows/gates.yml" <<'WIRING'
name: Gates
on:
  push:
jobs:
  gates:
    runs-on: ubuntu-24.04
    steps:
      - run: ./scripts/verify-gates.sh
WIRING

  # A manifest naming one gate, so each control isolates exactly one judgement.
  # Each control names exactly one gate in the manifest *and* rewrites the
  # synthetic runner to invoke only that gate, so a control is isolated on both
  # dimensions. Registering one gate while the runner lists six would make every
  # control report the wiring mismatch instead of the gate's own behaviour, and
  # a control that always reports the same thing is not a control.
  #
  # Defined before the first call rather than after it. Bash resolves a function
  # name when the call *executes*, so a definition further down the body leaves
  # every call above it a "command not found" -- one that writes to stderr, does
  # nothing, and leaves the fixture unwired while the control below still reports
  # what it wants to hear. Takes a list, so a control can register two gates.
  # `wiring_repo` rather than a parameter, so the controls below that build a
  # second fixture repository can point this at it. A hard-wired $repo left that
  # fixture with no runner at all, and every control in it reported exit 2 --
  # "inconclusive" -- which reads as a broken control rather than a broken
  # fixture, and would have been easy to mistake for the audit being right.
  local wiring_repo="$repo"
  # A gate is not always under scripts/. The Python skill gates live in tools/,
  # and a hard-coded prefix made the runner list a path the manifest never named
  # -- so the forward check reported a missing entry and every skill control
  # turned red for a wiring reason rather than a gate reason.
  local wiring_prefix='scripts/'
  write_wiring() {
    cat > "$wiring_repo/scripts/verify-gates.sh" <<WIRING
#!/usr/bin/env bash
gate_cmds=(
  "scripts/$META_NAME --self-test"
WIRING
    local g
    for g in "$@"; do
      printf '  "%s%s"\n' "$wiring_prefix" "$g" >> "$wiring_repo/scripts/verify-gates.sh"
    done
    printf ')\n' >> "$wiring_repo/scripts/verify-gates.sh"
  }
  write_wiring honest-gate.sh

  gate_control() {
    local label="$1" want="$2" gate="$3"
    printf 'git-tree scripts/%s\n' "$gate" > "$repo/$MANIFEST_NAME"
    write_wiring "$gate"
    audit "$repo" >/dev/null 2>&1
    status=$?
    if [ "$status" -ne "$want" ]; then
      echo "self-test FAILED: $label (wanted exit $want, got $status)" >&2
      failures=$((failures + 1))
    else
      echo "self-test ok: $label (exit $status)"
    fi
  }

  gate_control accepts-an-honest-gate 0 honest-gate.sh
  gate_control refuses-the-shape-that-shipped 1 fix-after-the-fact-gate.sh
  gate_control refuses-a-gate-that-always-passes 1 always-clean-gate.sh
  gate_control refuses-a-gate-that-always-refuses 1 always-two-gate.sh
  gate_control refuses-a-gate-that-only-refuses 1 only-refuses-gate.sh

  # A manifest naming a gate that is not there: a registration that silently
  # stops being checked is the same failure as a gate that stops running. The
  # runner is rewritten first, so the missing file is the only defect -- left
  # over from the previous control it would also trip the unregistered-gate
  # check below, and this control would pass without its own defect mattering.
  #
  # The exit code alone is not enough to assert here, and this control is where
  # that was proven. Executing a script that does not exist yields 127, the
  # verdict check rejects that, and the audit exits 1 -- so with the presence
  # check deleted this control still passed. It passed for the wrong reason and
  # with the wrong words: the finding read "reported exit 127, not 2", which
  # describes a gate that ran and misbehaved rather than one that is not
  # installed. A gate that cannot tell you what it looked at is the defect this
  # whole file exists to catch, and the auditor itself is not exempt from it, so
  # this control asserts the diagnosis as well as the exit code.
  printf 'git-tree scripts/not-installed.sh\n' > "$repo/$MANIFEST_NAME"
  write_wiring not-installed.sh
  local said
  said="$(audit "$repo" 2>&1 | grep -v mavis-trash)"
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "self-test FAILED: refuses-a-missing-gate (wanted exit 1, got $status)" >&2
    failures=$((failures + 1))
  elif ! printf '%s\n' "$said" | grep -qF 'not present and executable'; then
    echo "self-test FAILED: refuses-a-missing-gate (exit 1, but not by saying the" \
      "gate is missing -- it refused for some other reason: $said)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-a-missing-gate (exit $status, named as missing)"
  fi

  # The direction that actually bites in practice: a gate that is still being run
  # but has fallen out of the manifest. Its output is still believed, and nothing
  # has ever asked whether it can distinguish a pass from a blank.
  #
  # Two things this has to get right, and one of them it did not. The runner is
  # reset to the honest gate first, because the previous control left its own
  # gate in the runner array -- and an unregistered gate is *also* what that
  # leftover produces, so the control passed while its own fixture contributed
  # nothing. And the extra gate has to be added as a real entry inside
  # `gate_cmds`, which is the only form the reverse check reads. Appending a
  # manifest-shaped line to a runner is neither valid bash nor an array element:
  # it is a bare command after the array has been closed, and the audit would
  # have walked straight past it. Proven by disabling the reverse check and
  # watching this control go red.
  write_wiring honest-gate.sh
  printf 'git-tree scripts/honest-gate.sh\n' > "$repo/$MANIFEST_NAME"
  cat > "$repo/scripts/never-registered-gate.sh" <<'GATE'
#!/usr/bin/env bash
exit 0
GATE
  chmod +x "$repo/scripts/never-registered-gate.sh"
  write_wiring honest-gate.sh never-registered-gate.sh
  audit "$repo" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "self-test FAILED: refuses-a-run-but-unregistered-gate (wanted exit 1, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-a-run-but-unregistered-gate (exit $status)"
  fi
  # Put the runner back, or every later control inherits the finding. The gate
  # file itself needs no cleanup: it lives under $tmp, which the RETURN trap
  # removes on the way out.
  write_wiring honest-gate.sh

  # A repository whose entry point is a Makefile rather than a script. This is
  # the shape that made the wiring check hard-coded in the first place, so it is
  # the case the configurable runner has to be proven on. The manifest declares
  # the runner, the CI file and the command, and the audit must accept the lot.
  local mk="$tmp/makefile-repo"
  mkdir -p "$mk/scripts" "$mk/.github/workflows"
  cat > "$mk/scripts/mk-honest-gate.sh" <<'GATE'
#!/usr/bin/env bash
set -uo pipefail
dir="${1:-.}"
[ -d "$dir" ] || exit 2
if [ -f "$dir/leak.txt" ]; then exit 1; fi
[ -f "$dir/clean.txt" ] || exit 2
exit 0
GATE
  chmod +x "$mk/scripts/mk-honest-gate.sh"
  cat > "$mk/Makefile" <<'MK'
.PHONY: check
check:
	@./scripts/mk-honest-gate.sh --self-test || true
	@./scripts/mk-honest-gate.sh
	@./scripts/check-gates-are-honest.sh --self-test
	@./scripts/check-gates-are-honest.sh
MK
  cat > "$mk/.github/workflows/check.yml" <<'WIRING'
name: Gates
on:
  push:
jobs:
  gates:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - name: make check
        run: make check
WIRING
  cat > "$mk/.gate-manifest" <<'MANIFEST'
# runner: Makefile
# ci-entry: .github/workflows/check.yml
# ci-command: make check

git-tree  path  scripts/mk-honest-gate.sh
MANIFEST
  # The meta-gate's own self-test is named by the Makefile above, so it has to be
  # reachable from this directory; the check is on the CI command and the runner
  # path, and the fixture exists so the file it names is really there.
  cp "${BASH_SOURCE[0]}" "$mk/scripts/$META_NAME"
  chmod +x "$mk/scripts/$META_NAME"
  audit "$mk" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "self-test FAILED: accepts-a-makefile-entry-point (wanted exit 0, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: accepts-a-makefile-entry-point (exit $status)"
  fi
  # And the same repository with the command removed from CI, which is the case
  # the hard-coded check could not have expressed at all.
  cat > "$mk/.github/workflows/check.yml" <<'WIRING'
name: Gates
on:
  push:
jobs:
  gates:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - name: build
        run: make build
WIRING
  audit "$mk" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "self-test FAILED: refuses-a-makefile-repo-whose-ci-drops-it (wanted exit 1, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-a-makefile-repo-whose-ci-drops-it (exit $status)"
  fi

  # The `skill-tree` kind and the `relocated` invocation, which exist for a gate
  # that resolves its own repository from its own file path. Python, in tools/,
  # driven by being copied into the fixture rather than by an argument.
  local sr="$tmp/skill-repo"
  mkdir -p "$sr/scripts" "$sr/tools" "$sr/.github/workflows"
  cp "${BASH_SOURCE[0]}" "$sr/scripts/$META_NAME"
  chmod +x "$sr/scripts/$META_NAME"

  # Honest on all three: one good skill, one a loader rejects, none at all.
  cat > "$sr/tools_probe.py" <<'PYGATE'
#!/usr/bin/env python3
"""Refuse a SKILL.md a loader would reject. Resolves its own root from __file__."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
skills = REPO / "skills"
if not skills.is_dir():
    print("no skills directory", file=sys.stderr)
    sys.exit(2)
found = sorted(skills.rglob("SKILL.md"))
if not found:
    # The case this whole family exists for: no subjects is not a clean tree.
    print("no SKILL.md under skills/", file=sys.stderr)
    sys.exit(2)
for skill in found:
    text = skill.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        print(f"  {skill}: no frontmatter", file=sys.stderr)
        sys.exit(1)
sys.exit(0)
PYGATE
  # The defect measured in elohim, in miniature: a skill gate that reports a
  # clean tree when it has no skills to look at. It is right about a real
  # finding and about a good skill, and wrong only about the case that reads as
  # a pass -- which is why it needs its own control rather than the
  # always-passes one.
  cat > "$sr/tools_blind.py" <<'PYGATE'
#!/usr/bin/env python3
"""Right about findings, wrong about having nothing to look at."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for skill in sorted((REPO / "skills").rglob("SKILL.md")):
    if not skill.read_text(encoding="utf-8", errors="replace").startswith("---"):
        sys.exit(1)
sys.exit(0)
PYGATE
  cat > "$sr/tools_always_two.py" <<'PYGATE'
#!/usr/bin/env python3
import sys
sys.exit(2)
PYGATE
  mkdir -p "$sr/tools"
  mv "$sr/tools_probe.py" "$sr/tools/probe-gate.py"
  mv "$sr/tools_blind.py" "$sr/tools/blind-gate.py"
  mv "$sr/tools_always_two.py" "$sr/tools/always-two.py"
  # Executable, because the audit refuses a registered gate that is not present
  # and executable at its path -- and a Python gate is a gate.
  chmod +x "$sr/tools/"*.py
  cat > "$sr/.github/workflows/gates.yml" <<'WIRING'
name: Gates
on:
  push:
jobs:
  gates:
    steps:
      - run: ./scripts/verify-gates.sh
WIRING
  skill_control() {
    local label="$1" want="$2" line="$3" gate="$4"
    printf '%s\n' "$line" > "$sr/$MANIFEST_NAME"
    wiring_repo="$sr"
    wiring_prefix='tools/'  # the skill gates are not under scripts/
    write_wiring "$gate"
    wiring_repo="$repo"
    wiring_prefix='scripts/'
    audit "$sr" >/dev/null 2>&1
    status=$?
    if [ "$status" -ne "$want" ]; then
      echo "self-test FAILED: $label (wanted exit $want, got $status)" >&2
      failures=$((failures + 1))
    else
      echo "self-test ok: $label (exit $status)"
    fi
  }
  skill_control accepts-an-honest-skill-gate 0 \
    'skill-tree relocated tools/probe-gate.py' probe-gate.py
  skill_control refuses-a-skill-gate-that-is-blind-to-an-empty-tree 1 \
    'skill-tree relocated tools/blind-gate.py' blind-gate.py
  skill_control refuses-a-skill-gate-that-always-refuses 1 \
    'skill-tree relocated tools/always-two.py' always-two.py
  # The relocated mode with a gate that audits nothing: it resolves its own
  # root, finds no skills, and answers 0. Written before the control that
  # drives it, because a control naming a file that does not exist yet is
  # testing the presence check rather than the gate.
  cat > "$sr/tools/ignores-args.py" <<'PYGATE'
#!/usr/bin/env python3
"""Resolves a root, looks at nothing, and reports a clean tree."""
import sys
sys.exit(0)
PYGATE
  chmod +x "$sr/tools/ignores-args.py"
  skill_control refuses-a-relocated-gate-that-audits-nothing 1 \
    'skill-tree relocated tools/ignores-args.py' ignores-args.py
  # And a gate driven the old way -- given a path it ignores -- is still caught,
  # because the mode is declared and the audit follows the declaration.
  skill_control refuses-an-unknown-invocation-mode 1 \
    'skill-tree teleport tools/probe-gate.py' probe-gate.py

  # The checksum table in docs/gates.md. A document that claims a copy matches
  # when it does not is the failure this file is about, one level up: the copies
  # are the thing being kept honest, and the table is what says they are. Both
  # controls run on the same fixture repository, differing only in the table, so
  # the later ones prove the first was reading the table and not something else
  # in the tree.
  mkdir -p "$repo/docs"
  write_wiring honest-gate.sh
  printf 'git-tree scripts/honest-gate.sh\n' > "$repo/$MANIFEST_NAME"
  local hmd5 hlines
  hmd5=$(md5sum "$repo/scripts/honest-gate.sh" | cut -d' ' -f1)
  hlines=$(wc -l < "$repo/scripts/honest-gate.sh")
  doc_control() {
    local label="$1" want="$2" sum="$3" lines="$4"
    cat > "$repo/docs/gates.md" <<DOCROW
| File | md5 | Lines |
|---|---|---|
| \`scripts/honest-gate.sh\` | \`$sum\` | $lines |
DOCROW
    audit "$repo" >/dev/null 2>&1
    status=$?
    if [ "$status" -ne "$want" ]; then
      echo "self-test FAILED: $label (wanted exit $want, got $status)" >&2
      failures=$((failures + 1))
    else
      echo "self-test ok: $label (exit $status)"
    fi
  }
  doc_control accepts-a-correct-checksum-table 0 "$hmd5" "$hlines"
  doc_control refuses-a-diverged-checksum 1 00000000000000000000000000000000 "$hlines"
  doc_control refuses-a-hand-edited-line-count 1 "$hmd5" 999
  # The row has to go back before the next controls, or every one of them
  # inherits a finding it did not earn.
  rm -f "$repo/docs/gates.md"

  # An unknown subject kind is a finding, not a skip.
  printf 'some-new-kind scripts/honest-gate.sh\n' > "$repo/$MANIFEST_NAME"
  audit "$repo" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 1 ]; then
    echo "self-test FAILED: refuses-an-unknown-subject-kind (wanted exit 1, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-an-unknown-subject-kind (exit $status)"
  fi

  # No manifest at all is inconclusive, not a pass: nothing was audited.
  local bare="$tmp/bare"
  mkdir -p "$bare"
  audit "$bare" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 2 ]; then
    echo "self-test FAILED: refuses-a-repo-with-no-manifest (wanted exit 2, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-a-repo-with-no-manifest (exit $status)"
  fi

  # The manifest exists but names nothing: a clean-looking pass that audited
  # zero gates is the exact bug, one level up.
  mkdir -p "$bare/scripts"
  printf '# nothing registered\n' > "$bare/$MANIFEST_NAME"
  audit "$bare" >/dev/null 2>&1
  status=$?
  if [ "$status" -ne 2 ]; then
    echo "self-test FAILED: refuses-an-empty-manifest (wanted exit 2, got $status)" >&2
    failures=$((failures + 1))
  else
    echo "self-test ok: refuses-an-empty-manifest (exit $status)"
  fi

  rm -rf "$tmp"
  trap - RETURN
  if [ "$failures" -ne 0 ]; then
    echo "self-test: $failures control(s) did not behave as specified" >&2
    return 1
  fi
  echo "self-test: an honest gate is accepted, and every dishonest one is named"
}

main() {
  if [ "${1:-}" = "--self-test" ]; then
    self_test
    return $?
  fi
  audit "${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
}

main "$@"
