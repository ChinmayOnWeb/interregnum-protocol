# Project Praetorian

## The Interregnum Protocol

The Interregnum Protocol is an agentic remediation system for abandoned or weakly maintained open-source packages. It takes a vulnerable package, classifies likely vulnerability classes, analyzes the dangerous code path, generates and scores multiple fix strategies, applies the strongest patch, validates the result with real tests, attacks the fix with adversarial payloads, and produces both a developer-facing dashboard and a detailed remediation summary.

This prototype was built for the OpenAI Codex Hackathon at Berkeley.

## What It Does

- Accepts a vulnerable package target
- Runs a multi-agent remediation workflow:
  - `Scout`: classifies likely vulnerability classes directly from source
  - `Spotter`: traces root cause and dangerous lines
  - `Striker`: generates multiple fix strategies, scores them, and patches
  - `Validator`: replays exploit and regression tests
  - `Adversary`: tries to break the patch with bypass payloads
  - `Debrief`: compiles the dashboard and detailed fix summary
- Measures agent quality with evals:
  - patch quality score
  - speed score
  - reliability log
  - patch resilience score

## Current Demo Targets

### 1. `mixin-deep`
- Ecosystem: `npm`
- CVE: `CVE-2019-10746`
- Class: Prototype Pollution

### 2. `set-value`
- Ecosystem: `npm`
- CVE: `CVE-2019-10747`
- Class: Prototype Pollution

### 3. `request`
- Ecosystem: `npm`
- CVE: `CVE-2023-28155`
- Class: SSRF / Insufficient Input Validation via cross-protocol redirect bypass

## Repo Structure

- [`run_pipeline.js`](D:\UCB\CODEX\run_pipeline.js): main orchestration entrypoint
- [`classify_vulnerabilities.js`](D:\UCB\CODEX\classify_vulnerabilities.js): Scout classifier
- [`analyzer.js`](D:\UCB\CODEX\analyzer.js): Spotter root-cause analysis
- [`patcher.js`](D:\UCB\CODEX\patcher.js): Striker strategy generation and patching
- [`verifier.js`](D:\UCB\CODEX\verifier.js): exploit + regression verification
- [`adversarial_tester.js`](D:\UCB\CODEX\adversarial_tester.js): hostile bypass attempts
- [`eval.js`](D:\UCB\CODEX\eval.js): patch quality, speed, and reliability scoring
- [`dashboard/`](D:\UCB\CODEX\dashboard): 3-screen demo web app
- [`vulnerable-package/`](D:\UCB\CODEX\vulnerable-package): vulnerable `mixin-deep` target
- [`vulnerable-package-2/`](D:\UCB\CODEX\vulnerable-package-2): vulnerable `set-value` target

## How To Run

### Offline demo mode

This is the most reliable hackathon path and requires no API credits.

```powershell
node D:\UCB\CODEX\run_pipeline.js --demo --target mixin-deep
node D:\UCB\CODEX\run_pipeline.js --demo --target set-value
node D:\UCB\CODEX\run_pipeline.js --demo --target request
```

### Live mode with OpenAI API

```powershell
$env:OPENAI_API_KEY="your_key_here"
node D:\UCB\CODEX\run_pipeline.js --target mixin-deep
node D:\UCB\CODEX\run_pipeline.js --target set-value
node D:\UCB\CODEX\run_pipeline.js --target request
```

### Run the dashboard

```powershell
node D:\UCB\CODEX\dashboard\server.js
```

Then open:

```text
http://localhost:4173
```

## Demo Flow

### Screen 1
- choose `Run demo package` or `Enter custom package`

### Screen 2
- watch the live remediation pipeline:
  - Scout
  - Spotter
  - Striker
  - Validator
  - Adversary
  - Debrief

### Screen 3
- switch between:
  - `Dashboard`
  - `Detailed Fix Summary`

## Outputs

The pipeline produces:

- `REMEDIATION_REPORT.md`
- `analyzer_output.json`
- `classification_output.json`
- `patch_output.json`
- `adversarial_results.json`
- `eval_results.json`
- `pipeline_run.json`

## Why This Matters

Modern software supply-chain tooling is good at detection, but much weaker at remediation when a package is abandoned. The Interregnum Protocol is designed around that gap: not just finding vulnerable packages, but generating a reviewable path toward fixing them.

## Hackathon Positioning

This project sits at the intersection of:

- Agentic workflows
- UX for agentic applications
- Domain agents
- Evals for agent performance

## Status

This is a hackathon prototype built for speed and demonstration value. It is intentionally scoped around real vulnerable package targets, deterministic offline demos, and a strong operator-facing UX.
