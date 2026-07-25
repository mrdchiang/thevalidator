/**
 * Shared Prompt Templates
 * =======================
 * @version 1.0.0
 *
 * Keyed prompt templates used across the Security Tools Suite.
 * Each export is a function(context) → { system, user }.
 *
 * CONVENTIONS:
 * - System prompts establish the AI's role and expertise
 * - User prompts contain the specific query with context variables injected
 * - Context objects should never contain unsanitized user input
 */

// ─── DEBUG_MISMATCH (TheValidator) ───────────────────────────────────────────

/**
 * Debug an endpoint health mismatch between what the management console
 * reports and what the endpoint actually shows.
 *
 * @param {Object} ctx
 * @param {string} ctx.hostname — Affected hostname
 * @param {string} ctx.os — Operating system
 * @param {string} ctx.tool — Tool being checked (e.g. "CrowdStrike", "Windows Update")
 * @param {string} ctx.consoleSays — What the management console reports
 * @param {string} ctx.endpointShows — What the endpoint actually reports
 * @param {string} ctx.mismatchField — The specific field that mismatches
 * @param {string} ctx.severity — Severity level (Critical/High/Medium/Low)
 * @returns {{ system: string, user: string }}
 */
export function DEBUG_MISMATCH(ctx = {}) {
  const {
    hostname = 'Unknown Host',
    os = 'Windows Server',
    tool = 'Unknown Tool',
    consoleSays = 'Unknown',
    endpointShows = 'Unknown',
    mismatchField = 'Unknown Field',
    severity = 'Medium',
  } = ctx;

  const system = `You are a senior Windows systems and security engineer. You're debugging an endpoint health mismatch between what the management console reports and what the endpoint actually shows. Be specific, give exact PowerShell commands and step-by-step troubleshooting.

Hostname: ${hostname}
OS: ${os}

MISMATCH:
Tool: ${tool}
Console reports: ${consoleSays}
Endpoint reports: ${endpointShows}
Mismatch field: ${mismatchField}
Severity: ${severity}

Possible causes:
- SCCM deployment failed or pending reboot
- Update policy not applied to this host group
- GPO or local policy blocking updates
- Network connectivity issue preventing check-in
- Service crash or hung process

What is the likely root cause and how do I fix it? Give exact commands.`;

  return {
    system,
    user: `Debug this mismatch: Why does the console say one thing but the endpoint shows another? What's the root cause and exact fix?`,
  };
}

// ─── REMEDIATION_PLAN (RemFlow) ──────────────────────────────────────────────

/**
 * Generate a complete remediation plan for a security vulnerability.
 *
 * @param {Object} ctx
 * @param {string} ctx.cve — CVE ID (e.g. "CVE-2026-12345")
 * @param {string} [ctx.name] — Vulnerability name / description
 * @param {string} [ctx.severity] — Critical | High | Medium | Low
 * @param {string} [ctx.os] — Affected OS
 * @param {string} [ctx.solution] — Vendor-provided solution guidance
 * @param {string} [ctx.kb] — KB article reference
 * @param {string} [ctx.extra] — Additional context
 * @returns {{ system: string, user: string }}
 */
export function REMEDIATION_PLAN(ctx = {}) {
  const {
    cve = 'Unknown CVE',
    name = 'Unknown',
    severity = 'Medium',
    os = 'Windows Server 2022',
    solution = 'Apply vendor patch/update',
    kb = 'None',
    extra = '',
  } = ctx;

  const system = `You are a senior Windows systems engineer with 20 years experience in vulnerability remediation. You work in an enterprise environment with Windows Server, Windows 10/11, and Linux servers.

Analyze this vulnerability and provide:
1. **Root Cause Assessment** — What is the vulnerability and how does it work?
2. **Step-by-Step PowerShell Remediation** — Exact PowerShell commands to fix it
3. **Verification Steps** — How to confirm the fix was applied
4. **Rollback Plan** — How to undo the change if needed

Context:
- CVE: ${cve}
- Name/Description: ${name}
- Severity: ${severity}
- Affected OS: ${os}
- Vendor Solution: ${solution}
- KB Reference: ${kb}
${extra}

Be specific with PowerShell cmdlets, registry paths, service names, and verification commands.`;

  return {
    system,
    user: `Generate a complete remediation plan for ${cve}.`,
  };
}

/**
 * Quick chat context for RemFlow — lightweight version used during free-form chat.
 *
 * @param {Object} ctx
 * @param {string} [ctx.cve]
 * @param {string} [ctx.name]
 * @param {string} [ctx.severity]
 * @param {string} [ctx.os]
 * @param {string} [ctx.solution]
 * @param {string} [ctx.extra]
 * @returns {{ system: string, user: string }}
 */
export function REMEDIATION_CHAT(ctx = {}) {
  const {
    cve = '',
    name = '',
    severity = '',
    os = 'Windows Server 2022',
    solution = 'Apply vendor patch',
    extra = '',
  } = ctx;

  const base = 'You are a Windows systems engineer. Help remediate vulnerabilities.';

  if (cve) {
    const parts = [
      `CVE: ${cve}`,
      name && `Name: ${name}`,
      severity && `Severity: ${severity}`,
      os && `OS: ${os}`,
      solution && `Solution: ${solution}`,
      extra,
    ].filter(Boolean).join(', ');

    return {
      system: `You are a Windows systems engineer. Help remediate this vulnerability. Context: ${parts}`,
      user: '',
    };
  }

  return { system: base, user: '' };
}

// ─── EXECUTIVE_SUMMARY (AskClippy) ───────────────────────────────────────────

/**
 * Generate an executive summary of the security posture.
 * Used by AskClippy to produce dashboard-facing summaries.
 *
 * @param {Object} ctx
 * @param {number} [ctx.totalFindings=0] — Total active findings
 * @param {number} [ctx.criticalCount=0] — Critical severity count
 * @param {number} [ctx.highCount=0] — High severity count
 * @param {number} [ctx.kevCount=0] — CISA KEV count
 * @param {number} [ctx.remediatedCount=0] — Remediated count
 * @param {number} [ctx.verifiedCount=0] — Verified count
 * @param {string} [ctx.dateRange='last 30 days'] — Reporting period
 * @returns {{ system: string, user: string }}
 */
export function EXECUTIVE_SUMMARY(ctx = {}) {
  const {
    totalFindings = 0,
    criticalCount = 0,
    highCount = 0,
    kevCount = 0,
    remediatedCount = 0,
    verifiedCount = 0,
    dateRange = 'last 30 days',
  } = ctx;

  const system = `You are a cybersecurity executive assistant. You write concise, actionable executive summaries for C-level leadership. Keep it brief, use bullet points, and always include a clear "bottom line" recommendation. Use plain language — avoid jargon.

CRITICAL RULES:
- Never exceed 6 bullet points
- Start with a one-sentence assessment
- End with a clear recommendation
- Use numbers and percentages where possible
- Be honest — don't sugarcoat bad news`;

  const user = `Write an executive summary of our vulnerability management posture for the ${dateRange}.

Current metrics:
- Total active findings: ${totalFindings}
- Critical severity: ${criticalCount}
- High severity: ${highCount}
- CISA Known Exploited (KEV): ${kevCount}
- Remediated: ${remediatedCount}
- Verified fixed: ${verifiedCount}

Include: overall assessment, what's working, what needs attention, and a recommendation.`;

  return { system, user };
}
