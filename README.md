# TheValidator — Endpoint Health Checker

[![Security Tools](https://img.shields.io/badge/Security-Tools-0066ff)](https://mrdchiang.github.io/security-tools/)
[![GitHub Pages](https://img.shields.io/badge/hosted-GitHub%20Pages-brightgreen)](https://mrdchiang.github.io/thevalidator/)

**Live:** https://mrdchiang.github.io/thevalidator/

A standalone, self-contained HTML dashboard for endpoint health validation, GPO drift detection, CIS benchmark compliance, EOL lifecycle management, and remediation verification. TheValidator is the **third step** in the ShieldView cross-tool pipeline — it verifies that RemFlow-deployed remediations actually resolved the issues on the endpoint.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Features](#features)
  - [Dashboard](#-dashboard)
  - [Assets & Asset Detail](#-assets--asset-detail)
  - [GPO Baseline Import & Drift Detection](#-gpo-baseline-import--drift-detection)
  - [CIS Benchmark Compliance](#-cis-benchmark-compliance)
  - [Console vs Endpoint Comparison](#-console-vs-endpoint-comparison)
  - [AI Debug Assistant (Ollama)](#-ai-debug-assistant-ollama)
  - [Pipeline Handoff](#-pipeline-handoff)
  - [EOL Lifecycle Management](#-eol-lifecycle-management)
  - [Software Version Tracking](#-software-version-tracking)
  - [Evidence Retention & Compliance Sparklines](#-evidence-retention--compliance-sparklines)
  - [Export & Reporting](#-export--reporting)
- [Architecture](#architecture)
- [Cross-Tool Pipeline](#cross-tool-pipeline)
- [Data Shape](#data-shape)
- [Health States & Check Results](#health-states--check-results)
- [Production Roadmap](#production-roadmap)
- [Deployment](#deployment)
- [Project Files](#project-files)
- [License & Contact](#license--contact)

---

## What It Does

TheValidator performs simulated agent health checks across 9 security tools on 42 endpoints. It detects GPO configuration drift by comparing actual endpoint settings against policy baselines, maps findings to CIS benchmarks, flags console-vs-endpoint mismatches, and verifies that RemFlow-deployed remediations actually resolved the issues — closing the verification loop.

All data is client-generated (no backend required). The tool reads from and writes to `localStorage` under the `security-tools:` namespace, sharing state with ShieldView, RemFlow, and the Launchpad.

---

## Features

### 📊 Dashboard

Six real-time stat cards summarize endpoint fleet health:

| Card | Description |
|------|-------------|
| **Total Endpoints** | Count of all managed endpoints |
| **Healthy** | All 9 checks passing |
| **Degraded** | Warnings or 2–3 failures |
| **Critical** | 4+ failed checks — immediate attention |
| **Offline** | No recent check-in |
| **Compliance Rate** | % of endpoints passing all checks |

Additional dashboard widgets:
- **Pipeline Status Bar** — RemFlow pending items → Verified → Ready for Launchpad
- **Pending Verifications** — Items awaiting verification after RemFlow deployment
- **GPO Drift Detection** — Summary of settings that have drifted from baseline
- **CIS Benchmark Compliance** — Circular score + compliance bar for 56 CIS controls
- **Top Issues** — Ranked bar of most-failing checks by endpoint count
- **Severity Distribution** — Stacked bar by Critical / High / Medium / Low
- **Software Version Summary** — Counts of total, up-to-date, outdated, and critical installations
- **Cross-Tool Banner** — Appears when RemFlow has completed remediations requiring verification

### 🖥️ Assets & Asset Detail

**Assets Page:** 42 searchable/filterable endpoints with columns for Hostname, IP, OS, Location, Health badge, Checks (passed/total), Last Check, and Status. Filter by health state, location (10 global sites), or OS family (Windows/macOS/Linux). Click any row to drill into asset detail.

**Asset Detail Page** provides per-endpoint deep-dive:

- **System Info:** IP, OS, Location, Function, Last Check, Overall Health
- **Check Results Table:** All 9 tools with Expected vs Actual values, Result badge, Last Verified timestamp, and **compliance sparklines** (last 10 check runs)
- **Flapping Detection:** Badge appears when a check flips state 3+ times in 30 days
- **Non-Compliance Duration:** Shows how many consecutive runs a check has been failing
- **Console vs Endpoint Comparison:** Side-by-side table of what the management console reports vs what the endpoint shows
- **GPO Compliance Table:** Per-policy status with CIS reference mapping, GPO source, drift warnings, and one-click fix commands
- **User Policy Impact:** Logon scripts, drive mappings, folder redirection, printer mappings — status and conflicts
- **Evidence Summary:** Total evidence records retained (180-day window)

**Detail Page Actions:**
| Button | Description |
|--------|-------------|
| ⚡ Run Health Check Now | Simulates a fresh health check and records all results to evidence history |
| 📊 Export Evidence | Downloads CSV of all historical check records for this asset |
| 📋 Export Fixes for PDQ/SCCM | Exports non-compliant GPO fix commands as a `.ps1` script |
| 🔍 View CVEs in ShieldView | Deep links to ShieldView filtered by hostname |
| 🛠️ Remediate via RemFlow | Deep links to RemFlow for remediation deployment |

### 📐 GPO Baseline Import & Drift Detection

Three-tab GPO management interface:

1. **Import Baseline**
   - Drag-and-drop CSV or HTML exports from `gpresult /h` or `Get-GPOReport`
   - Support for both CSV and GPResult HTML parsing
   - Demo baseline: 20 pre-configured policies (password, audit, firewall, Defender, BitLocker, UAC, RDP, PowerShell, LAPS)
   - Clear baseline action

2. **Baseline Summary**
   - Total policies, configured vs not-configured counts
   - Full table with Policy Name, Setting, Value, Scope, Status, and CIS Reference mapping

3. **Drift Detection**
   - Compares current endpoint GPO state against imported baseline
   - Per-policy per-hostname drift table with CIS references
   - Drift history snapshots (up to 10 retained)
   - Dashboard integration with badge counter on sidebar navigation

### 🏛️ CIS Benchmark Compliance

**56 CIS controls** mapped across three benchmarks:
- **CIS Windows 10** — 35 controls (Account Policies, Audit Policy, Security Options, Firewall, Advanced Audit, LAPS, UAC, Defender, RDP, Privacy, PowerShell, BitLocker)
- **CIS Windows Server 2019** — 7 controls
- **CIS Windows Server 2022** — 7 controls (+ Defender Exploit Guard)

Features:
- Circular score card (color-coded: green ≥80%, yellow ≥50%, red <50%)
- Compliance bar showing Compliant / Non-Compliant / Not Configured segments
- Searchable/filterable controls table (by status, benchmark, or text search)
- Each control shows: CIS Ref, Name, Benchmark, Category, Expected value, GPO Setting, Current state, Status
- Dashboard mini-view with summarized score

Controls auto-map to GPO settings via a lookup index — no manual mapping required.

### 🔍 Console vs Endpoint Comparison

Compares what **management consoles** report against what **endpoints actually show** for 9 security tools:

| Tool | Console Source |
|------|---------------|
| CrowdStrike Falcon Sensor | Falcon Console |
| Windows Defender | SCCM / Intune |
| Tenable Agent | Tenable.io |
| Zscaler Client | Zscaler Admin Portal |
| SCCM Client | Configuration Manager |
| BitLocker | MBAM / SCCM |
| OS Patch Level | WSUS / SCCM |
| LAPS | Active Directory |
| Duo/MFA Agent | Duo Admin Panel |

Features:
- **~22% simulated mismatch rate** — realistic drift across versions, service states, and policies
- **Summary stats:** Assets compared, Total checks, Matching, Mismatches, Match rate %
- **Per-asset breakdown** with color-coded severity (Critical / High / Medium / Low)
- **One-click actions per mismatch:**
  - 📤 **Push to RemFlow** — Queues a remediation with the exact fix command
  - 📋 **Run Locally** — Copies the PowerShell remediation command to clipboard
  - 🪄 **AI Debug** — Opens the AI Debug Assistant with full context
- CSV import support for external console exports (columns: Hostname, Tool, Console Value, Endpoint Value, Match, Field, Severity)
- Demo data loader for quick evaluation
- Remediation map with 27 specific fixes across all 9 tools

### 🪄 AI Debug Assistant (Ollama)

Integrated LLM-powered debugging panel that analyzes endpoint health mismatches using a **local Ollama instance** (`http://localhost:11434`).

- **Shared Ollama client** (`js/shared/ollama-client.js`) — typed errors, streaming & non-streaming, connection health checks
- **Shared prompt templates** (`js/shared/prompts.js`) — role-engineered `DEBUG_MISMATCH` prompt with full context injection
- **Model selector** — auto-populated from available Ollama models (llama3.2, mistral, codellama, phi3:mini, deepseek-coder-v2, etc.)
- **Streaming chat panel** with typing indicators, copy-code buttons, and retry
- **Fallback mode** — when Ollama is unavailable, provides a structured static troubleshooting guide:
  - Root cause assessment (SCCM deployment failure, GPO blocking, network issues, hung services, pending reboot)
  - Recommended fix with exact PowerShell command
  - 6-step troubleshooting checklist with specific commands
- **Chat history** preserved for follow-up questions in session
- **CSP:** `connect-src 'self' http://localhost:11434` — Ollama is the only external connection

### 🔄 Pipeline Handoff

TheValidator is the verification step in the **Security Tools Suite** pipeline:

```
ShieldView (Find) → RemFlow (Remediate) → TheValidator (Verify) → Launchpad (Report)
```

**Pipeline Page features:**
- **Import from RemFlow** — reads pending/deployed remediations from `security-tools:remediation-queue`
- **Preview stats** — deployed count, pending count
- **Per-item verification** — mark individual remediations as verified with evidence
- **Verify All** — batch-verify all pending remediations
- **Verified Queue (Phase 1.1)** — write-back to `security-tools:verified-queue` for ShieldView to display verification status
- **Push to Launchpad** — forward verified items to `security-tools:launchpad-queue`
- **Verified History** — full audit trail of all verified remediations
- **Clear Queue** — with confirmation prompt

**localStorage Keys Used:**
```
security-tools:remediation-queue       (read from RemFlow)
security-tools:validated-remediations  (written by TheValidator)
security-tools:verified-queue          (write-back for ShieldView)
security-tools:launchpad-queue         (forward to Launchpad)
security-tools:last-launchpad-push     (timestamp tracking)
```

### 🕐 EOL Lifecycle Management

Four-tab lifecycle dashboard for hardware and OS refresh planning:

1. **EOL Overview**
   - Stat cards: Supported / Approaching EOL / End of Life / Unknown
   - Searchable/filterable endpoint table: Hostname, OS, Type, EOL Date, Days Left, Status badge, Upgrade Path
   - EOL database covers 15 OS versions across Windows, macOS, and Linux
   - Auto-detection of hardware type (Workstation / Laptop / Server) from hostname

2. **Replacement Groups (by Quarter)**
   - Assets approaching EOL or past EOL grouped by target quarter
   - Each group shows: asset count, priority (🔴 High / 🟡 Medium / 🟢 Low), **total estimated cost**
   - Expandable group detail with per-asset cost breakdown
   - **Push to RemFlow** — creates EOL replacement projects with cost estimates in the remediation queue

3. **Upgrade Paths**
   - Four documented paths:
     - Windows 10 → Windows 11 23H2 (SCCM Task Sequence, 2–4 weeks)
     - Windows Server 2012 R2/2016 → Server 2022 (In-Place or Migrate, 1–2 weeks)
     - Ubuntu 20.04 LTS → 22.04 LTS (`do-release-upgrade`, 1–2 hours)
     - RHEL 8.x → RHEL 9.x (Leapp, 30 min–1 hour)
   - Numbered step-by-step instructions with exact commands

4. **Timeline (Next 18 Months)**
   - Color-coded dot visualization per quarter
   - Dots are hoverable — tooltip shows hostname, OS, and EOL date
   - Legend: 🟢 Supported / 🟡 Approaching (≤180d) / 🔴 EOL / ⚫ Unknown

### 💿 Software Version Tracking

Tracks **20 IT software packages** across all endpoints with **live version fetching** from vendor APIs:

| Category | Software | Version Source |
|----------|----------|---------------|
| Browser | Chrome, Firefox, Edge | Omahaproxy, Mozilla API, Edge Update API |
| Office | Microsoft 365 Apps | Microsoft 365 release notes API |
| Collaboration | Teams, Zoom, Slack | Microsoft, Zoom, Slack APIs |
| PDF | Adobe Acrobat Reader | Adobe Reader version feed |
| Utility | 7-Zip, Notepad++, WinSCP, PuTTY, Everything, Sysinternals, Beyond Compare | GitHub Releases, vendor feeds |
| Runtime | Java (Adoptium), Python, PowerShell 7, Git | GitHub Releases |
| Media | VLC Media Player | GitHub Releases |

Features:
- Live fetch on page load with fallback versions when offline
- Status classification: Current / Outdated / Critical
- Search, filter (by status and category), and sort (by name, category, vendor, outdated count, critical count)
- Dashboard summary card with 4 stats
- CSV export

### 📋 Evidence Retention & Compliance Sparklines

**Append-Only Evidence History:**
- Every health check run appends records to `security-tools:validator-check-history`
- **180-day retention window** — older records are automatically pruned
- Each record captures: asset hostname, check name, timestamp, expected value, actual value, result (pass/fail/warn)
- Evidence summary on asset detail page shows total records and check runs

**Derived Metrics:**
| Metric | Description |
|--------|-------------|
| **Compliance Sparklines** | Inline 10-bar miniature chart showing pass/fail/warn for last 10 check runs. Hover shows date and result. |
| **Flapping Detection** | Identifies checks that flip state 3+ times in 30 days — flagged with "🔄 Flapping" badge |
| **Non-Compliance Duration** | Counts consecutive failing runs — flagged with "⏱ N runs non-compliant" badge |
| **GPO Drift History** | Snapshots of baseline changes (up to 10 retained) |

### 📤 Export & Reporting

| Export | Format | Description |
|--------|--------|-------------|
| Evidence CSV | `.csv` | Per-asset historical check records (Asset, Check, Timestamp, Expected, Actual, Result) |
| Fix Commands | `.ps1` | PowerShell script of non-compliant GPO remediation commands for PDQ/SCCM deployment |
| Software Versions | `.csv` | Current software inventory with versions and status counts |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Security Tools Suite                       │
│                                                              │
│  ShieldView ──→ RemFlow ──→ TheValidator ──→ Launchpad      │
│   (Find)        (Remediate)    (Verify)        (Report)      │
│                                                              │
│   All share: localStorage (security-tools:* namespace)       │
│   All share: js/shared/{contract, ollama-client, prompts}    │
└──────────────────────────────────────────────────────────────┘
```

TheValidator is a **single-file HTML application** (~4,500 lines) with three shared JS modules:

| Module | Purpose |
|--------|---------|
| `js/shared/contract.js` | Data contract — key registry, record types (JSDoc), validators, safe accessors, audit trail |
| `js/shared/ollama-client.js` | Unified Ollama client — `/api/chat` streaming, non-streaming, `/api/generate`, typed errors, connection check |
| `js/shared/prompts.js` | Keyed prompt templates (DEBUG_MISMATCH, REMEDIATION_PLAN, EXECUTIVE_SUMMARY) |

All CSS is inline in the `<style>` block — no external stylesheets. Dark theme (`#060b18` root background) with sidebar navigation, responsive breakpoints, and accessibility-friendly contrast.

---

## Cross-Tool Pipeline

### Read from RemFlow
```javascript
function checkCrossToolQueue() {
  return JSON.parse(localStorage.getItem('security-tools:remediation-queue') || '[]')
    .filter(i => i.status === 'pending' || i.status === 'deployed');
}
```

### Write Verification Evidence
```javascript
// After verifying a remediation, write back to verified-queue for ShieldView
verifiedQueue.push({
  findingId: item.id,
  asset: item.asset,
  cve: item.cve,
  verifiedAt: new Date().toISOString(),
  verifiedByTool: 'thevalidator',
  checkName: item.checkName,
  evidence: 'Expected X, Found X — MATCH',
  expected: item.expected,
  actual: item.actual,
  result: 'pass'
});
localStorage.setItem('security-tools:verified-queue', JSON.stringify(verifiedQueue));
```

### Push to Launchpad
```javascript
// Forward verified items
const validated = JSON.parse(localStorage.getItem('security-tools:validated-remediations') || '[]');
const launchpad = JSON.parse(localStorage.getItem('security-tools:launchpad-queue') || '[]');
validated.forEach(item => launchpad.push({...item, pushedAt: now, source: 'TheValidator Pipeline'}));
```

---

## Data Shape

### Asset
```javascript
{
  hostname: "CORP-WS7421",
  ip: "10.23.45.67",
  os: "Windows 11 Enterprise",
  loc: "HQ-NYC",
  function: "Engineering",
  health: "healthy",              // healthy | degraded | critical | offline
  last: "2026-07-24 14:22",
  passed: 9,
  total: 9,
  checks: [                       // 9 tools
    {
      name: "Endpoint Protection Agent",
      expected: "Running | Version 7.8+",
      actual: "Running v7.9.2",
      result: "pass",             // pass | fail | warn
      last: "2026-07-24 14:22"
    }
  ],
  compare: [                      // Console vs Endpoint
    { name: "Endpoint Protection Agent", console: "Running v7.9.2", endpoint: "Running v7.9.2", match: "✅" }
  ],
  gpo: [                          // 12 GPO policies
    {
      name: "Password Policy — Min Length",
      gpoVal: "14 characters",
      endpointVal: "14 characters",
      compliant: "Compliant",
      gpoSource: "Default Domain Policy",
      userOverride: null          // Local Admin Override | Conflicting User GPO | etc.
    }
  ],
  userPolicies: [                 // User policy impact
    { name: "Map H: Drive", type: "Drive Mapping", source: "Default Domain Policy", status: "Applied", ... }
  ],
  software: [                     // Software inventory
    { name: "Google Chrome", vendor: "Google", category: "Browser", expected: "132.0.6834", installed: "132.0.6834", status: "current" }
  ],
  isOffline: false
}
```

### CIS Control
```javascript
{
  ref: "1.1.1",
  name: "Enforce password history",
  benchmark: "win10",             // win10 | win2019 | win2022
  category: "Account Policies",
  expected: "24 passwords remembered",
  gpoSetting: "Password must meet complexity requirements",
  status: "compliant",            // compliant | non-compliant | not-configured
  currentVal: "24 passwords remembered",
  compliantEndpoints: 42,
  totalEndpoints: 42
}
```

---

## Health States & Check Results

### Endpoint Health
| State | Meaning | Trigger | Color |
|-------|---------|---------|-------|
| `healthy` | All checks passing | 0 failures, ≤2 warnings | 🟢 Green |
| `degraded` | Warnings or minor failures | 2–3 failures OR ≥3 warnings | 🟠 Orange |
| `critical` | Major failures | ≥4 failed checks | 🔴 Red |
| `offline` | No recent check-in | Every 11th asset simulated | ⚪ Gray |

### Check Results
| Result | Meaning | Example |
|--------|---------|---------|
| `pass` | Endpoint matches expected value | Encryption: Encrypted (100%) = Encrypted |
| `fail` | Endpoint deviates from expected | Protection Agent: Running → Stopped |
| `warn` | Partial compliance or elevated risk | Patch Level: Latest Rollup → Missing 2 Security |

### Critical Rule: No Vendor Names in Generic Tools
The 9 generic health check tools use descriptive names, not vendor products:
- ✅ `Endpoint Protection Agent`, `ZTNA Client`, `Encryption Status`
- ✅ `Config Mgmt Agent`, `Multi-Factor Auth`, `OS Patch Level`
- ❌ `CrowdStrike Falcon`, `Microsoft Defender`, `Zscaler`, `BitLocker`

*(The Console vs Endpoint comparison page uses real vendor names since it specifically compares console-reported state.)*

---

## Production Roadmap

TheValidator is currently a **client-side demo** — all data is generated in the browser. To build a production version:

### Step 1: Data Sources
| Data | Demo Source | Production Source |
|------|------------|-------------------|
| Endpoint inventory | `genAsset()` randomization | Microsoft Intune, Jamf, AD, SCCM |
| Health checks | `genChecks()` random pass/fail/warn | Endpoint Protection Agent API, ZTNA client API, MDE API |
| GPO compliance | Simulated drift with 12 policies | Active Directory GPO results, PolicyAnalyzer, `gpresult` |
| Software inventory | `genSoftwareInv()` random | SCCM Inventory, Intune managed apps, PDQ Inventory |
| Console vs Endpoint | `generateConsoleDemoData()` | SCCM WMI, CrowdStrike API, Tenable API, Zscaler API |

### Step 2: Health Check Integration
```javascript
async function runHealthChecks(hostname) {
  const checks = [
    fetch(`/api/endpoint/${hostname}/protection/status`),
    fetch(`/api/endpoint/${hostname}/encryption/status`),
    fetch(`/api/endpoint/${hostname}/patching/status`),
    fetch(`/api/endpoint/${hostname}/ztna/status`),
  ];
  return Promise.all(checks.map(p => p.catch(() => ({ status: 'offline' }))));
}
```

### Step 3: GPO Drift Detection
```javascript
async function checkGPOCompliance(hostname) {
  const baseline = await fetch('/api/gpo/baseline').then(r => r.json());
  const actual = await fetch(`/api/endpoint/${hostname}/gpo/actuals`).then(r => r.json());
  return baseline.map(policy => ({
    ...policy,
    compliant: policy.expectedValue === actual[policy.name],
    actualValue: actual[policy.name]
  }));
}
```

### Step 4: Production Concerns
| Concern | Mitigation |
|---------|-----------|
| **Agent communication** | WebSocket or gRPC streaming for real-time check-in |
| **GPO baselines** | Store in version-controlled YAML, deploy via SCCM Baseline |
| **Verification frequency** | Configurable: every 15min (critical) / 1hr (standard) / daily (non-critical) |
| **Remediation verification** | After RemFlow deploys, automatically trigger health check on affected endpoints |
| **Reporting** | Export to CSV, PDF, or email weekly compliance summary |
| **Ollama integration** | Deploy Ollama on a central server; configure `setBaseUrl()` for shared access |
| **Evidence retention** | Replace localStorage with IndexedDB or server-side audit log for longer retention |

---

## Deployment

### GitHub Pages (current)
```yaml
# .github/workflows/pages.yml
name: Deploy to GitHub Pages
on:
  push:
    branches: [main]
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: '.'
      - id: deployment
        uses: actions/deploy-pages@v4
```

**Required repo files:**
- `index.html` — the application (single-file, ~4,500 lines)
- `.nojekyll` — disables Jekyll processing on GitHub Pages
- `.github/workflows/pages.yml` — auto-deploy workflow
- `404.html` — hash routing fallback for direct URLs (e.g. `/thevalidator/asset/CORP-WS7421`)
- `js/shared/*.js` — shared modules (contract, ollama-client, prompts)

### Deep-Link Routing
TheValidator supports hash-based deep linking:
- `/#/assets` — Assets page
- `/#/asset/CORP-WS7421` — Direct asset detail view
- `/#/issues` — Issues page
- `/#/gpo-baseline` — GPO Baseline
- `/#/cis` — CIS Compliance
- `/#/console-endpoint` — Console vs Endpoint
- `/#/pipeline` — Pipeline Handoff
- `/#/lifecycle` — EOL Lifecycle
- `/?hostname=CORP-WS7421` — URL param support (redirects to hash route)

---

## Project Files

| File | Lines | Purpose |
|------|-------|---------|
| `index.html` | ~4,550 | Main application — HTML, CSS, and JavaScript in a single file |
| `js/shared/contract.js` | 420 | Shared data contract — key registry, record types, validators, safe accessors |
| `js/shared/ollama-client.js` | 454 | Ollama API client — streaming, non-streaming, typed errors, connection check |
| `js/shared/prompts.js` | 212 | Shared prompt templates (DEBUG_MISMATCH, REMEDIATION_PLAN, EXECUTIVE_SUMMARY) |
| `404.html` | 24 | GitHub Pages hash routing fallback |
| `.nojekyll` | 0 | Disables Jekyll processing |
| `.github/workflows/pages.yml` | ~20 | Auto-deploy to GitHub Pages |
| `assets/*.svg` | — | Demo screenshots (dashboard, assets, detail) |
| `README.md` | — | This file |

---

## License & Contact

Built by **David Chiang** as part of the [ShieldView Security Tools Suite](https://mrdchiang.github.io/security-tools/).

📧 [mrdavidchiang@gmail.com](mailto:mrdavidchiang@gmail.com)

**Live:** https://mrdchiang.github.io/thevalidator/
