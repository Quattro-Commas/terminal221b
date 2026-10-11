[![CI](https://github.com/Quattro-Commas/terminal221b/actions/workflows/ci.yml/badge.svg)](https://github.com/Quattro-Commas/terminal221b/actions/workflows/ci.yml)
[![Gates](https://github.com/Quattro-Commas/terminal221b/actions/workflows/gates.yml/badge.svg)](https://github.com/Quattro-Commas/terminal221b/actions/workflows/gates.yml)
[![CodeQL](https://github.com/Quattro-Commas/terminal221b/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Quattro-Commas/terminal221b/actions/workflows/github-code-scanning/codeql)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Node >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org/)

# Terminal221b

Terminal221b is an Expo/React Native chat client and an installable, local-first coding CLI.
The CLI sends selected workspace text to Anthropic and requires explicit approval before applying a proposed diff.

## Why it exists

The mobile app remains a single-screen Claude chat client. Separate TypeScript CLI and Rust TUI packages provide bounded local-workspace context, local security triage, and reviewed patch workflows. The repository does not implement autonomous multi-agent orchestration, blockchain transactions, local TensorRT inference, or an economic loop.

## Architecture

```mermaid
flowchart TD
    subgraph Mobile["Existing mobile and web app"]
      User --> App["Expo app"]
      App --> Chat["ChatScreen"]
      Chat --> Store["Zustand chat store"]
      Store --> Sessions["AsyncStorage: sessions and non-secret settings"]
      Store --> Key["SecureStore on iOS and Android"]
      Chat --> Service["ClaudeService"]
    end
    subgraph Terminal["Terminal CLI"]
      Developer --> CLI["terminal221b ask"]
      CLI --> Context["Bounded workspace context"]
      CLI --> Approval["Explicit diff review and approval"]
      Approval --> GitApply["git apply (after approval)"]
      CLI --> LocalScan["Local-only security triage"]
      CLI --> Scope["Bounty scope manifest validation"]
      CLI --> Dossier["Local case dossier (offline)"]
      Bundle["Operator case bundle JSON"] --> Dossier
      CLI --> Tools["Installed tool discovery"]
    end
    subgraph ShellTUI["Rust shell TUI"]
      Operator --> TUI["Ratatui + Crossterm"]
      TUI --> Editor["Unicode prompt editor"]
      TUI --> Transcript["Local save/list/load"]
      TUI --> Preview["/context preflight"]
      Preview --> LocalWorker["Local worker"]
      LocalWorker --> Paths["Paths + byte sizes only"]
      TUI --> ChatRequest["Chat request"]
      ChatRequest --> Worker["Provider worker"]
      Worker --> Workspace["Bounded workspace context"]
      Workspace --> API
    end
    Service --> API["Anthropic Messages API"]
    CLI --> API
    API --> Service
```

`App.tsx` loads the persisted store. `ChatScreen` handles the chat UI and settings for a user-provided API key. `ClaudeService` sends the conversation to Anthropic and returns the first text block in the response. The native app keeps the API key in SecureStore; web builds keep it in memory only.

## Quickstart

### Requirements

- Node.js 22
- npm
- Expo Go or a configured iOS/Android development environment for native use
- An Anthropic API key for live chat requests

### Install and run

```sh
git clone https://github.com/Quattro-Commas/terminal221b.git
cd terminal221b
npm ci
npm run start
```

Open the project in Expo Go or a configured simulator. In the app, open **Settings**, enter your own API key, save it, then send a chat message.

To start the web development server, run `npm run web`. To create the web export used by CI, run `npm run build`; output is written to the ignored `dist/` directory. Web storage is not secure for API keys, so the app keeps the key in memory only on web and live browser API calls have not been verified.

### Environment

The mobile app does not load API keys from `.env` files. The terminal CLI reads `ANTHROPIC_API_KEY` from the invoking process environment; never use `EXPO_PUBLIC_*` for secrets because client bundle values are public.

For the full picture — every dependency and why it is here, the complete install and verification ladder for all three surfaces, the TUI module map, the prompt framework, the designer workflow spec, the smart-contract toolchains, and the phase-by-phase integration plan — see the [engineering guide](docs/TERMINAL221B-ENGINEERING-GUIDE.md).

## Usage

After saving a key in Settings, type a message and select **Send**. The app submits the message history and displays the first text block returned by the API. Exact model output varies and a live API response was not captured for this change.

The deterministic service test uses this input and mocked response:

```text
Input message: Hello
Mock API text block: A mocked reply
ClaudeService result: A mocked reply
```

The test validates request headers, model and token defaults, and error handling without making a network request.

## Terminal CLI

The `@terminal221b/cli` workspace builds the `terminal221b` command with Node.js 22 or later. The Rust workspace adds an original full-screen terminal interface using Ratatui and Crossterm.

```sh
npm ci
npm run build:cli
npm run cli -- ask --workspace . "Summarize the source layout"
```

Build and launch the Rust TUI:

```sh
cargo build --release -p terminal221b-tui
cargo install --path packages/rust-tui --locked
terminal221b tui .
```

The TUI supports multi-turn Anthropic chat, a crypto-focused system prompt via `/crypto`, tool discovery via `/tools`, a local analyzer run via `/scan`, `/apply <request>` for a proposed unified diff, and local transcript commands `/save <name>`, `/sessions`, and `/load <name>`. It previews all patch paths and diff text; press `y` to apply or `n` to reject. `Enter` submits, `Shift+Enter` inserts a line break, the arrow keys edit the prompt, and `Home`/`End` move to the current line boundaries (`Ctrl+A`/`Ctrl+E` are also supported). `PageUp`/`PageDown` scroll the conversation by a viewport-sized page and clamp at its oldest/newest content. Set `ANTHROPIC_API_KEY` in the environment; `TERMINAL221B_MODEL` optionally selects a model. The TUI uses bounded local context and does not execute model-generated commands.

Saved sessions contain only user and assistant transcript turns; system messages, the workspace path, automatically collected workspace context, provider configuration, and API keys are not saved. Obvious API-token assignments, bearer tokens, and private-key blocks are redacted before writing, but local transcript files are plain text and this heuristic is not a guarantee that every secret is detected. On Unix, the session directory is restricted to mode `0700` and files to `0600`; on Windows, files use inherited directory permissions. Storage is atomic and local: `$XDG_STATE_HOME/terminal221b/sessions` when set, otherwise `~/.local/state/terminal221b/sessions` on Unix, or `%LOCALAPPDATA%/terminal221b/sessions` on Windows. Session names are limited to 48 lowercase ASCII letters, digits, hyphens, and underscores.

The terminal interface is an actual shell TUI, so it uses Ratatui/Crossterm rather than Tauri. Tauri is a desktop-webview framework; a Tauri desktop wrapper is not part of this terminal release. See the [TUI architecture decision](docs/TUI-ARCHITECTURE.md) for a researched comparison of agent TUI stacks and the reasons this project stays with Rust/Ratatui.

The TUI command `/context` locally previews the selected workspace file paths and byte sizes without printing source bodies or contacting Anthropic. A future request re-collects context, so the displayed selection may change if files change. The CLI reads a bounded set of text files (up to 80 files and 256 KB total), skips hidden files, symlinks, dependency/build folders, and common environment files, then sends that context and the prompt to Anthropic. Set `ANTHROPIC_API_KEY` in the shell before using it. Files leave the machine for the configured Anthropic endpoint; do not run it on a workspace you are not willing to share with that provider.

To request a code change, add `--apply`. The CLI accepts only a unified diff, rejects workspace traversal, symlink paths, binary diffs, and secret-file destinations, validates the patch with `git apply --check`, shows the diff, and writes only if you type `APPLY`. It never executes model-generated shell commands.

For crypto-focused text chat about project architecture, protocol/NFT ideas, or market mechanics:

```sh
terminal221b crypto ask --workspace ./my-project "Review this Solana program's account model"
```

This mode sends the selected local text context to Anthropic like `ask`; it is not a live market-data feed or autonomous agent. It does not provide personalized investment recommendations, place trades, sign transactions, manage wallet keys, or contact bounty targets.

### Local security triage and toolchains

```sh
terminal221b security scan --workspace .
terminal221b tools
terminal221b scope validate examples/bounty-scope.example.json
```

`security scan` runs built-in heuristics and only runs optional analyzers explicitly selected by flags:

```sh
terminal221b security scan --workspace . \
  --with-gitleaks --with-bandit --with-semgrep --with-trivy \
  --with-slither --with-cargo-audit
```

Gitleaks and Bandit scan local files; Semgrep uses bundled local rules with metrics disabled; Trivy runs offline and skips database updates; Slither examines discovered Solidity files without invoking a project build; cargo-audit uses the cached advisory database with fetching disabled. Findings are reduced to path, line, rule, and severity; scanner source excerpts and secret values are not printed. Trivy requires a previously cached vulnerability database for dependency findings, and cargo-audit requires a cached advisory database. Update those databases separately when network access is permitted. These tools are not a complete security review and findings are not proof of exploitability. `tools` only checks whether supported tools are on `PATH`; it neither executes nor installs them.

The scope manifest is data for local review only. Wildcards and non-HTTPS targets are rejected; out-of-scope paths override an in-scope path prefix. Terminal221b currently has no remote target-testing feature. Do not test any program asset without checking its current rules and obtaining authorization.

### Local case dossier

```sh
terminal221b case template > case-bundle.json
terminal221b case dossier case-bundle.json --now 2026-09-30T12:00:00Z --policy-max-age-days 90
```

`case dossier` reads one local case bundle and prints a markdown dossier to stdout. It is offline: it makes no network request, contacts no target, and calls no provider. `--now` defaults to the current time and `--policy-max-age-days` defaults to 90; that default is a working threshold for this tool, not a rule from any program.

A bundle carries versioned case, source, evidence, task, approval, confirmation, program, duplicate-search, assessment, and outcome records. Parsing is fail-closed: an unrecognised field or value is an error, never a default. Sign/transfer is not an available capability, an approval, confirmation, outcome, duplicate search, or assessment can only be recorded by a human, a `paid` outcome requires a receipt reference, and a `fact` claim requires deterministic or operator-confirmed verification.

A case reaches the actionable queue only when all of the following hold: its asset normalizes to one exact HTTPS URL and is inside the recorded scope, the policy snapshot it cites is within the freshness limit, the program publishes a bounty for that asset type, a `fact` claim carries deterministic verification, and a `ConfirmationRecord` pins that exact asset to that exact policy snapshot **and** carries a signature that verifies against a key a case store trusts. A wildcard or ambiguous asset is held for review, never queued. A confirmation recorded against a superseded snapshot does not carry over. The asset identity is derived from `assetOriginal` by rule and cannot be supplied independently of it. Without `--store` the gate has no key set and stays shut, so a confirmed case is reported as awaiting a signature rather than as queued.

The dossier splits cases into `ELIGIBLE`, `REVIEW`, `BLOCKED`, and `NOT EVALUATED`, and only eligible cases enter the actionable queue. Every `REVIEW` names what it is waiting on, and a case whose evaluation failed is reported rather than dropped. Ranking uses an ordinal factor vector with no weights and no aggregate score, so there is no expected-payout or payout-probability number anywhere. Factors the bundle cannot determine stay `unknown`, and `unknown` never outranks a known level. `novelty` is derived from a recorded duplicate search, and a search that found nothing scores `medium` rather than `high`, because a search cannot prove absence. An operator assessment may state a level for `impact_fit`, `novelty`, `effort`, or `reward_fit`, must cite a record, and may lower a derived level but never raise it; an assessment that is refused is reported under the case rather than dropped. `impact_fit` and `reward_fit` stay `unknown` unless an assessment cites the program record, because mapping a finding to a published severity category is a human act.

The bundle is the operator's own file, not a case database, and a [local case store](docs/TERMINAL221B-CASE-STORE.md) can hold and vouch for it (see below). Retention classes still record an intention rather than enforce it — nothing is deleted. Freshness is measured from an operator-recorded timestamp, so `freshness: high` is a statement about your record-keeping and not about the policy; [the freshness review](docs/TERMINAL221B-FRESHNESS-REVIEW.md) states the arithmetic, the boundary, and the manual steps the CLI cannot take for you. Untrusted bundle text is stripped of control characters and escaped before it is printed. `case template` prints a fixture bundle built entirely from non-resolvable `example.invalid` URIs. See [the case threat model](docs/TERMINAL221B-CASE-THREAT-MODEL.md) before rendering a bundle from any untrusted source; it records the open findings, chiefly that a signature names a key rather than a person, that only local source digests are recomputed, and that `writablePaths` is validation-at-parse with no executor behind it.

Built-in scans use deterministic local heuristic patterns. Gitleaks and Bandit run only if explicitly selected with `--with-gitleaks` or `--with-bandit`; Gitleaks scans the selected workspace, while Bandit receives the Python source files found by Terminal221b. Both are local-only, capture structured output, discard secret values returned by scanners, and print only the finding path/rule/line. Other discovered analyzers are not invoked automatically.

### Local case store

```sh
STORE=~/.local/share/terminal221b

terminal221b case store init --store "$STORE" \
  --public-key operator.pub --key-id operator-key
terminal221b case sign case-bundle.json --key operator.pem --key-id operator-key > signed.json
terminal221b case store put signed.json --store "$STORE" --base-dir .
terminal221b case store get case-exact-in-scope --store "$STORE"
terminal221b case store verify --store "$STORE"
```

A local directory holding case bundles: trusted public keys, one file per revision, a content-addressed copy of each, and an append-only transition log. The root defaults to `$XDG_DATA_HOME/terminal221b`; keep it **outside any repository**, because a store inside a git tree commits its attestations and its operator key ids.

`case sign` reads an ed25519 private key from a file you name, signs in memory, and writes only the signed JSON to stdout. The private key is never copied, logged, or written into a bundle or the store; the store holds the public half only, and registering the same key id twice is refused.

`put` verifies before it writes anything, in this order: every provenance link resolves, every human-authored record is signed by a key the store trusts, and every reachable local source's bytes hash to their declared digest. A refusal names the offending records or the source and both digests. `get` and `verify` re-run the same checks, and `verify` additionally compares each stored bundle against the digest recorded when that revision was written.

Local source digests are recomputed; remote ones are not. An `https://` source, and a `file://` URI naming a host, are recorded `unverifiable-here` and are never fetched — the CLI performs no egress — so every put, get, and verify prints the split, e.g. `2 source(s) verified locally, 3 unverifiable here`. `case store retention` ages every stored source against the window its class carries and purges what is past it; no window is built in, because how long data may be kept is an open decision, and a class with no window is reported rather than treated as safe to delete. A signature still names a key rather than a person. [The store document](docs/TERMINAL221B-CASE-STORE.md) has the exact signature bytes, the check order, and the list of things it does not do.

For Omarchy/Arch Linux, `terminal221b setup omarchy --dry-run` prints a package plan. It queries enabled official pacman package metadata but never installs packages, elevates privileges, builds AUR packages, or runs upstream installers. AUR candidates require manual `PKGBUILD` and source review. Gitleaks, Trivy, and cargo-audit are available from official Arch repositories. Foundry's upstream installer verifies release binary hashes; Slither and Semgrep can be isolated with pipx. Solana CLI and Anchor/AVM follow their upstream installation instructions. This project does not install host tools automatically.

To install just the CLI into a temporary user prefix for a smoke test:

```sh
npm pack --workspace @terminal221b/cli --pack-destination /tmp
npm install --global --prefix /tmp/terminal221b-prefix /tmp/terminal221b-cli-0.1.0.tgz
/tmp/terminal221b-prefix/bin/terminal221b --help
```

For normal use, install into a user-writable prefix and add that prefix's `bin` directory to `PATH`. The package is distributed under AGPL-3.0; see LICENSE for network-source disclosure requirements.

The CLI currently supports one Anthropic provider and one-shot prompts. It does not execute model-directed tools, maintain multi-turn sessions, call external bounty targets, run Solana transactions, or replace dedicated security analyzers. Crypto ideas and project analysis can be discussed with the existing chat prompt, but the CLI does not trade NFTs/tokens, manage wallets, or submit bounty reports.

## Status and limitations

- Primary language: TypeScript; the coding TUI is a Rust/Cargo package. The app uses Expo SDK 54, React Native, Zustand, AsyncStorage, SecureStore, and the Anthropic Messages API.
- Implemented: one chat screen, locally persisted sessions, a native API-key settings field, native secure key storage, direct text requests, a Rust TUI with local transcript save/list/load, Unicode-aware prompt editing, viewport conversation navigation, local `/context` disclosure preview, a local offline case dossier with fail-closed contracts, a signed human-confirmation eligibility gate, derived asset identity, an explainable ordinal rank vector, and a local case store that verifies signatures and recomputes local source digests before accepting a bundle.
- Not implemented: any agent, adapter, scheduler, or orchestration, role profiles beyond `analyst` (`scout`, `engineer`, `artist`, and `reviewer` are still labels that select the coding profile, F26), a Textual workbench, remote or read-only external data sources, blockchain or Solana transaction features, remote bounty testing, a general autonomous tool loop, TensorRT/local inference, a backend proxy, cross-run session persistence, mobile model selection, streaming, or attachment handling.
- Chat history remains in AsyncStorage and is not encrypted. Native API keys are stored in OS secure storage. Web API keys are memory-only.
- This is a client app that sends the user-provided key directly to Anthropic; it is not suitable for embedding an operator-owned key in a distributed build.
- The web export and TypeScript checks pass locally, but no simulator/device session or live Anthropic request has been verified.
- `npm audit --omit=dev` reports unresolved advisories in the dependency tree, including critical and high severity findings. Major Expo upgrades were not applied automatically.
- The repository is licensed under AGPL-3.0, which is not a permissive license like MIT. See LICENSE for details.

## Roadmap

1. Write the remaining evidence-backed agent profiles. `analyst` is shipped and reachable through `terminal221b ask --role analyst PROMPT`, rendered from the same `provider-boundary.json` the CLI and the TUI share; the other four roles still select the coding profile (F26). Each one that lands must change no existing output — today's CLI output is the regression test.
2. Add cancellable provider requests, streaming responses, and explicit offline/error states. The typed boundary that made these possible is already in place; this item is the user-facing half.
3. Add a separate Tauri desktop frontend if there is a clear desktop UX need; the shell TUI remains independent.
4. Expand local Solana/SVM development profiles; tool discovery alone does not configure or run chain tools.
5. Review and resolve dependency advisories without an untested Expo major upgrade.
6. Keep the open findings in the [case threat model](docs/TERMINAL221B-CASE-THREAT-MODEL.md) closed before a case bundle from an untrusted source is accepted by the store: a signature currently names a key rather than a person (F15) and only local source digests are recomputed (F16). **F17 is closed for the write path** — `executor.ts` enforces a task's declared write set by binding `/` read-only inside `bwrap`, drops the network namespace, and refuses to run at all when `bwrap` is absent rather than falling back. The remaining limits are that this is Linux-and-bubblewrap only and that `--allow-unsandboxed` disables it on purpose.
7. ~~Record the retention policy and give the Engineer adapter an isolated worktree~~ **Both done (2026-10-02).** The policy is `transient` 7d, `case_metadata` 180d, `local_diff` 180d, `operator_archive` never, held in `DEFAULT_RETENTION_POLICY` in `store.ts` and written to the operator's own `retention.json`. The isolated worktree is `executor.ts`: one `git worktree` per task under `.terminal221b/tasks/<taskId>`. **Phase 1 graduates.** Still to come in Phase 3: streaming status, cancellation, and an Engineer-bay screen.

## Support

The repository links to both GitHub Sponsors profiles for voluntary support only. There are no paid features; Sponsor checkout and payout have not been verified.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local checks.

## License

The repository is distributed under the terms in [LICENSE](LICENSE). The license is AGPL-3.0; network use requires source disclosure. See LICENSE for full terms.

## Security

See [SECURITY.md](SECURITY.md). Do not place API keys in Expo public environment variables or commit them to the repository.
