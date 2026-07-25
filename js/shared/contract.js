/**
 * Security Tools Suite — Shared Data Contract
 * =============================================
 * @version 2.0.0
 * 
 * Zero-dependency ES module defining the localStorage contract between
 * ShieldView, RemFlow, TheValidator, AskClippy, and the Launchpad.
 * 
 * All five apps are subpaths of the same origin (mrdchiang.github.io),
 * so they share one localStorage namespace. This module is the single
 * source of truth for every key, record shape, and access pattern.
 *
 * v2.0.0 CHANGES (Phase 2):
 * - FindingStateMachine + RemediationStatusMachine with legal transition maps
 * - Canonical state enforcement via transitionFinding() / transitionRemediation()
 * - Fixed 12 Phase 0 defects (validation bugs, quota handling, idempotency)
 * - Added assetId to Asset schema
 * - Added getStorageQuota() for proactive quota management
 * - All existing v1 APIs preserved — no breaking changes
 *
 * CONVENTIONS:
 * - All timestamps are ISO 8601 with timezone (e.g. "2026-07-24T20:45:00Z")
 * - All state transitions append to an audit trail, never overwrite history
 * - Accessors never throw on malformed data — they degrade visibly
 * - Every key is namespaced under "security-tools:"
 */

// ─── Version ────────────────────────────────────────────────────────────────
export const CONTRACT_VERSION = '2.0.0';

// ─── Key Registry ───────────────────────────────────────────────────────────
/**
 * Frozen registry of every localStorage key used across the suite.
 * All code must reference these constants — never string literals.
 */
export const KEYS = Object.freeze({
  // ── Debug ──────────────────────────────────────────────────────────────
  /** Shared error log across all tools */
  ERROR_LOG:               'security-tools:error-log',

  // ── ShieldView — Import ────────────────────────────────────────────────
  /** @type {Finding[]} Tenable/Nessus imported vulnerability findings */
  IMPORTED_FINDINGS:        'security-tools:imported-findings',
  /** Metadata: { lastImport, fileName, recordCount, columns[] } */
  IMPORTED_FINDINGS_META:   'security-tools:imported-findings-meta',
  /** @type {Asset[]} SCCM/PDQ imported device assets */
  IMPORTED_ASSETS:          'security-tools:imported-assets',
  /** Metadata: { lastImport, fileName, recordCount, columns[] } */
  IMPORTED_ASSETS_META:     'security-tools:imported-assets-meta',
  /** @type {Asset[]} Snipe-IT imported/loaded assets */
  SNIPEIT_ASSETS:           'security-tools:snipeit-assets',
  /** Metadata: { lastFetch, count, status } */
  SNIPEIT_ASSETS_META:      'security-tools:snipeit-assets-meta',
  /** Snipe-IT API config: { url, key?, mode, lastFetch } */
  SNIPEIT_CONFIG:           'security-tools:snipeit-config',

  // ── ShieldView — Live Feeds ────────────────────────────────────────────
  /** Cached CISA KEV catalog: { lastFetch, vulnerabilities: {} } */
  KEV_CATALOG:              'security-tools:kev-catalog',
  /** Contract version stamp (written by first app to load) */
  CONTRACT_VERSION_KEY:     'security-tools:contract-version',
  /** Migration tracking: { fromVersion, toVersion, migratedAt, recordCounts{} } */
  CONTRACT_MIGRATION:       'security-tools:contract-migration',

  // ── RemFlow — Remediation Pipeline ─────────────────────────────────────
  /** @type {Remediation[]} ShieldView→RemFlow handoff queue */
  REMEDIATION_QUEUE:         'security-tools:remediation-queue',
  /** Last remediation that was sent */
  LAST_REMEDIATION:          'security-tools:last-remediation',
  /** @type {object[]} SCCM/PDQ deployment records */
  REMFLOW_DEPLOYMENTS:       'security-tools:remflow-deployments',
  /** ISO 8601 timestamp of last ShieldView→RemFlow import */
  REMFLOW_LAST_IMPORT:       'security-tools:remflow-last-import',

  // ── TheValidator — Verification ────────────────────────────────────────
  /** @type {Verification[]} RemFlow→TheValidator verified results */
  VALIDATED_REMEDIATIONS:    'security-tools:validated-remediations',
  /** @type {Verification[]} Phase 1.1: TheValidator→ShieldView write-back */
  VERIFIED_QUEUE:            'security-tools:verified-queue',
  /** GPO baseline: { policies[], importedAt, source } */
  VALIDATOR_GPO_BASELINE:    'security-tools:validator-gpo-baseline',
  /** GPO baseline history snapshots */
  VALIDATOR_GPO_HISTORY:     'security-tools:validator-gpo-baseline-history',
  /** ISO 8601 of last TheValidator→Launchpad push */
  LAST_LAUNCHPAD_PUSH:       'security-tools:last-launchpad-push',
  /** @type {object[]} Verified items pushed to Launchpad */
  LAUNCHPAD_QUEUE:           'security-tools:launchpad-queue',

  // ── Exception Tracking (v2) ────────────────────────────────────────────
  /** @type {Exception[]} Formal exception records (false positives, risk accepted, deferred) */
  EXCEPTIONS:                'security-tools:exceptions',

  // ── RemFlow — Ring & Deployment Config ──────────────────────────────────
  /** Ring deployment configuration: { pilot: number, broad: number, full: number } */
  RING_CONFIG:               'security-tools:ring-config',
  /** Ring-specific remediation groupings */
  RING_REMEDIATIONS:         'security-tools:ring-remediations',
  /** Maintenance window config */
  MW_CONFIG:                 'security-tools:mw-config',
  /** Blackout date ranges (no deployments during) */
  BLACKOUT_DATES:            'security-tools:blackout-dates',

  // ── App Config ─────────────────────────────────────────────────────────
  /** UI theme preference */
  THEME:                     'security-tools:theme',
  /** Check/validation history across tools */
  CHECK_HISTORY:             'security-tools:check-history',
});

// ─── Record Types (JSDoc schema definitions) ────────────────────────────────

/**
 * @typedef {Object} Finding
 * @property {number} [id] — Unique identifier within the session
 * @property {string} cve — CVE ID (e.g. "CVE-2026-12345"). May be "NO-CVE-{pluginID}" for non-CVE findings.
 * @property {string} check — Plugin/check name from scanner (e.g. "Apache Log4j RCE")
 * @property {string} asset — Hostname of the affected asset (e.g. "WEB-PROD-03")
 * @property {string} port — Affected port/protocol (e.g. "443/tcp", "0/tcp")
 * @property {string} severity — "Critical" | "High" | "Medium" | "Low" | "None"
 * @property {string} state — "Active" | "Fixed" | "Actioned" | "Risk Accepted" | "False Positive" | "Deferred" | "Verified"
 * @property {boolean} kev — Whether this CVE is in CISA's Known Exploited Vulnerabilities catalog
 * @property {string} firstSeen — ISO 8601 date (YYYY-MM-DD)
 * @property {string} [lastSeen] — ISO 8601 date of last scan where this appeared
 * @property {string} [solution] — Remediation guidance from Tenable Solution field
 * @property {string} [description] — Scanner description
 * @property {string} [synopsis] — Scanner synopsis
 * @property {string} [fixedAt] — ISO 8601 timestamp when fixed
 * @property {string} [verifiedAt] — ISO 8601 timestamp when verified
 * @property {string} [verifiedByTool] — Tool that verified ("thevalidator")
 * @property {string} [lastVerificationFailedAt] — ISO 8601 timestamp of last failed verification
 * @property {string} [dueDate] — ISO 8601 date — remediation deadline (from KEV or severity policy)
 * @property {string} [ou] — Organizational Unit (enriched from SCCM/PDQ)
 * @property {string} [deviceUser] — Last logged on user (enriched from SCCM/PDQ)
 * @property {string[]} [serverRoles] — Server roles (enriched from SCCM/PDQ)
 * @property {string} [team] — Assigned team: "Endpoint" | "Factory" | "Networking" | "Servers"
 * @property {string} [assetOS] — OS string from asset data
 * @property {string} [warrantyStatus] — "Active" | "Expired" | "Expiring" | "Unknown"
 * @property {string} [snipeAssignedUser] — Assigned user from Snipe-IT
 * @property {string} [snipePurchaseDate] — Purchase date from Snipe-IT
 * @property {string} [snipeDepartment] — Department from Snipe-IT
 * @property {Object[]} [auditTrail] — Ordered list of state change records
 * @property {string} auditTrail[].timestamp — ISO 8601
 * @property {string} auditTrail[].fromState — Previous state
 * @property {string} auditTrail[].toState — New state
 * @property {string} auditTrail[].reason — Human-readable reason
 * @property {string} [auditTrail[].source] — "manual" | "remflow" | "thevalidator" | "shieldview"
 * @property {string} [exceptionId] — ID of linked Exception record (if applicable)
 */

/**
 * @typedef {Object} Asset
 * @property {string} hostname — Primary key, matched case-insensitively
 * @property {string} [assetId] — Unique asset identifier for cross-referencing (v2)
 * @property {string} [os] — Operating system (e.g. "Windows Server 2022 Datacenter")
 * @property {string} [ou] — Organizational Unit DN
 * @property {string} [deviceUser] — Last logged on user
 * @property {string[]} [serverRoles] — Inferred or explicit server roles
 * @property {string} [team] — "Endpoint" | "Factory" | "Networking" | "Servers"
 * @property {string} [lastSeen] — ISO 8601 timestamp
 * @property {string} [assetTag] — Asset tag from Snipe-IT (e.g. "SRV-00289")
 * @property {string} [serial] — Serial number
 * @property {string} [manufacturer] — Manufacturer name
 * @property {string} [model] — Model name
 * @property {string} [location] — Physical location
 * @property {string} [assignedTo] — Assigned user name
 * @property {string} [purchaseDate] — YYYY-MM-DD
 * @property {number} [warrantyMonths] — Warranty duration in months
 * @property {string} [warrantyStatus] — "Active" | "Expired" | "Expiring" | "Unknown"
 */

/**
 * @typedef {Object} Remediation
 * @property {string} [id] — Unique identifier
 * @property {string} cve — CVE ID being remediated
 * @property {string} name — Human-readable name (e.g. "Apache Log4j — 6 assets")
 * @property {string[]} assets — Affected hostnames
 * @property {string} severity — "Critical" | "High" | "Medium" | "Low"
 * @property {string} status — "pending" | "queued" | "deployed" | "failed" | "blocked"
 * @property {string} [solution] — Remediation guidance text
 * @property {string} [kb] — KB article ID if applicable
 * @property {string} [psCommand] — Generated PowerShell remediation command
 * @property {string} [rollbackCommand] — Rollback command
 * @property {string} [rollbackUnavailableReason] — Why rollback cannot be generated
 * @property {string} [ring] — "pilot" | "broad" | "full"
 * @property {number} [deployedCount] — Number of assets where deployed
 * @property {number} [verifiedCount] — Number of assets verified fixed
 * @property {string} [createdAt] — ISO 8601
 * @property {string} [deployedAt] — ISO 8601
 * @property {Object[]} [auditTrail]
 */

/**
 * @typedef {Object} Verification
 * @property {string} [id] — Unique identifier
 * @property {number|string} findingId — The Finding.id this verifies
 * @property {string} asset — Hostname verified
 * @property {string} cve — CVE ID
 * @property {string} verifiedAt — ISO 8601 timestamp
 * @property {string} verifiedByTool — "thevalidator"
 * @property {string} checkName — Name of the check (e.g. "CrowdStrike Sensor Version")
 * @property {string} evidence — Expected-vs-actual values that proved the result
 * @property {string} result — "pass" | "fail"
 * @property {string} [expected] — Expected value
 * @property {string} [actual] — Actual value
 */

/**
 * @typedef {Object} Exception
 * @property {string} id — Unique identifier
 * @property {string} findingId — Linked finding ID
 * @property {string} cve — CVE ID
 * @property {string} asset — Affected hostname
 * @property {string} type — "falsePositive" | "riskAccepted" | "deferred"
 * @property {string} reason — Business justification
 * @property {string} approvedBy — Approver name/role
 * @property {string} createdAt — ISO 8601
 * @property {string} expiresAt — ISO 8601 expiry date
 * @property {string} [reviewedAt] — ISO 8601 of last review
 * @property {string} status — "active" | "expired" | "revoked"
 */

// ─── Canonical State Machines (v2) ──────────────────────────────────────────

/**
 * FindingStateMachine — canonical states and legal transitions for vulnerability findings.
 * 
 * Uses ShieldView's real state vocabulary (v2.0.0 bugfix — aligned with validateFinding).
 * 
 * State lifecycle:
 *   Active ──→ Actioned ──→ Fixed ──→ Verified
 *    │            │            │
 *    └────────────┴─────→ Risk Accepted / False Positive / Deferred
 * 
 * Any terminal state can be reopened back to Active.
 */
export const FindingStateMachine = Object.freeze({
  /** Canonical states in lifecycle order (ShieldView vocabulary) */
  states: Object.freeze([
    'Active',
    'Actioned',
    'Fixed',
    'Verified',
    'Risk Accepted',
    'False Positive',
    'Deferred',
  ]),

  /** Default state for newly created findings */
  defaultState: 'Active',

  /** Terminal states (no outgoing transitions except reopen to Active) */
  terminalStates: Object.freeze(['Fixed', 'Verified', 'False Positive', 'Risk Accepted']),

  /**
   * Legal transition map: fromState → [legal toStates]
   * An omitted fromState means no restrictions (any state can transition to anything).
   * A fromState present with an empty array means dead-end (no transitions out).
   */
  transitions: Object.freeze({
    'Active':          ['Actioned', 'Fixed', 'Risk Accepted', 'False Positive', 'Deferred'],
    'Actioned':        ['Active', 'Fixed', 'Risk Accepted', 'False Positive'],
    'Fixed':           ['Verified', 'Active'],
    'Verified':        ['Active'],
    'Risk Accepted':   ['Active'],
    'False Positive':  ['Active'],
    'Deferred':        ['Active', 'Actioned'],
  }),
});

/**
 * RemediationStatusMachine — canonical statuses and legal transitions for remediation plans.
 * 
 * Pipeline:
 *   pending → queued → deployed → verified
 *                        │
 *                        ├── failed
 *                        └── rolledBack
 * 
 * failed / blocked remediations can be retried back to pending or queued.
 */
export const RemediationStatusMachine = Object.freeze({
  /** Canonical statuses in pipeline order */
  states: Object.freeze([
    'pending',
    'queued',
    'deployed',
    'verified',
    'failed',
    'blocked',
    'rolledBack',
  ]),

  /** Default status for newly created remediations */
  defaultStatus: 'pending',

  /** Terminal statuses (good outcomes — no further action needed) */
  terminalStatuses: Object.freeze(['verified', 'rolledBack']),

  /**
   * Legal transition map: fromStatus → [legal toStatuses]
   */
  transitions: Object.freeze({
    'pending':    ['queued', 'failed', 'blocked'],
    'queued':     ['deployed', 'failed', 'blocked'],
    'deployed':   ['verified', 'failed', 'rolledBack'],
    'verified':   [],   // terminal — no further transitions
    'failed':     ['pending', 'queued'],   // retry
    'blocked':    ['pending', 'queued'],   // retry after unblock
    'rolledBack': [],   // terminal
  }),
});

// ─── State Transition Helpers (v2) ──────────────────────────────────────────

/**
 * Check whether a finding state transition is legal.
 * @param {string} fromState — Current state
 * @param {string} toState — Proposed new state
 * @returns {boolean}
 */
export function isLegalFindingTransition(fromState, toState) {
  if (!fromState || !toState) return false;
  if (fromState === toState) return true; // idempotent — same state is always legal
  const legal = FindingStateMachine.transitions[fromState];
  if (!legal) return false;
  return legal.includes(toState);
}

/**
 * Check whether a remediation status transition is legal.
 * @param {string} fromStatus — Current status
 * @param {string} toStatus — Proposed new status
 * @returns {boolean}
 */
export function isLegalRemediationTransition(fromStatus, toStatus) {
  if (!fromStatus || !toStatus) return false;
  if (fromStatus === toStatus) return true; // idempotent
  const legal = RemediationStatusMachine.transitions[fromStatus];
  if (!legal) return false;
  return legal.includes(toStatus);
}

/**
 * Transition a Finding to a new state if legal, appending an audit entry.
 * Idempotent: calling with the same state is a no-op (returns the record unchanged).
 * 
 * @param {Object} finding — A Finding record (mutated in place)
 * @param {string} toState — Target state
 * @param {string} reason — Human-readable reason for the transition
 * @param {string} [source] — "manual" | "remflow" | "thevalidator" | "shieldview"
 * @returns {{ success: boolean, fromState: string, toState: string, error?: string }}
 */
export function transitionFinding(finding, toState, reason, source) {
  if (!finding) {
    return { success: false, fromState: '(none)', toState: toState || '(none)', error: 'Finding is null or undefined' };
  }
  if (!toState || typeof toState !== 'string') {
    return { success: false, fromState: finding.state || '(none)', toState: '(none)', error: 'toState is required and must be a string' };
  }
  if (!reason || typeof reason !== 'string') {
    return { success: false, fromState: finding.state || '(none)', toState, error: 'reason is required and must be a string' };
  }

  const fromState = finding.state || FindingStateMachine.defaultState;

  // Idempotency: same state is a no-op
  if (fromState === toState) {
    return { success: true, fromState, toState };
  }

  // Validate the transition
  if (!isLegalFindingTransition(fromState, toState)) {
    return {
      success: false,
      fromState,
      toState,
      error: `Illegal transition: "${fromState}" → "${toState}". Legal transitions from "${fromState}": [${(FindingStateMachine.transitions[fromState] || []).join(', ')}]`
    };
  }

  // Perform the transition
  finding.state = toState;
  appendAudit(finding, fromState, toState, reason, source);

  return { success: true, fromState, toState };
}

/**
 * Transition a Remediation to a new status if legal, appending an audit entry.
 * Idempotent: calling with the same status is a no-op.
 * 
 * @param {Object} remediation — A Remediation record (mutated in place)
 * @param {string} toStatus — Target status
 * @param {string} reason — Human-readable reason
 * @param {string} [source] — "manual" | "remflow" | "thevalidator"
 * @returns {{ success: boolean, fromStatus: string, toStatus: string, error?: string }}
 */
export function transitionRemediation(remediation, toStatus, reason, source) {
  if (!remediation) {
    return { success: false, fromStatus: '(none)', toStatus: toStatus || '(none)', error: 'Remediation is null or undefined' };
  }
  if (!toStatus || typeof toStatus !== 'string') {
    return { success: false, fromStatus: remediation.status || '(none)', toStatus: '(none)', error: 'toStatus is required and must be a string' };
  }
  if (!reason || typeof reason !== 'string') {
    return { success: false, fromStatus: remediation.status || '(none)', toStatus, error: 'reason is required and must be a string' };
  }

  const fromStatus = remediation.status || RemediationStatusMachine.defaultStatus;

  // Idempotency
  if (fromStatus === toStatus) {
    return { success: true, fromStatus, toStatus };
  }

  // Validate the transition
  if (!isLegalRemediationTransition(fromStatus, toStatus)) {
    return {
      success: false,
      fromStatus,
      toStatus,
      error: `Illegal transition: "${fromStatus}" → "${toStatus}". Legal transitions from "${fromStatus}": [${(RemediationStatusMachine.transitions[fromStatus] || []).join(', ')}]`
    };
  }

  // Perform the transition
  remediation.status = toStatus;
  appendAudit(remediation, fromStatus, toStatus, reason, source);

  return { success: true, fromStatus, toStatus };
}

// ─── Validators ──────────────────────────────────────────────────────────────

/**
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateFinding(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['finding is null or undefined'] };
  
  if (!obj.cve || typeof obj.cve !== 'string') errors.push('cve: required string');
  if (!obj.asset || typeof obj.asset !== 'string') errors.push('asset: required string');
  if (!obj.severity || !['Critical','High','Medium','Low','None'].includes(obj.severity))
    errors.push(`severity: must be Critical|High|Medium|Low|None, got "${obj.severity}"`);
  if (!obj.state || !['Active','Fixed','Actioned','Risk Accepted','False Positive','Deferred','Verified'].includes(obj.state))
    errors.push(`state: must be Active|Fixed|Actioned|Risk Accepted|False Positive|Deferred|Verified, got "${obj.state}"`);
  if (obj.firstSeen && !isISODate(obj.firstSeen)) errors.push('firstSeen: must be ISO 8601 date (YYYY-MM-DD)');
  if (obj.lastSeen && !isISODate(obj.lastSeen) && !isISOTimestamp(obj.lastSeen))
    errors.push('lastSeen: must be ISO 8601 date (YYYY-MM-DD) or timestamp');
  if (obj.dueDate && !isISODate(obj.dueDate)) errors.push('dueDate: must be ISO 8601 date (YYYY-MM-DD)');
  if (obj.fixedAt && !isISOTimestamp(obj.fixedAt)) errors.push('fixedAt: must be ISO 8601 timestamp');
  if (obj.verifiedAt && !isISOTimestamp(obj.verifiedAt)) errors.push('verifiedAt: must be ISO 8601 timestamp');
  if (obj.lastVerificationFailedAt && !isISOTimestamp(obj.lastVerificationFailedAt))
    errors.push('lastVerificationFailedAt: must be ISO 8601 timestamp');
  if (obj.auditTrail && !Array.isArray(obj.auditTrail)) errors.push('auditTrail: must be an array');
  
  return { valid: errors.length === 0, errors };
}

/**
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateAsset(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['asset is null or undefined'] };
  
  if (!obj.hostname || typeof obj.hostname !== 'string') errors.push('hostname: required string');
  if (obj.assetId && typeof obj.assetId !== 'string') errors.push('assetId: must be a string');
  if (obj.warrantyMonths && typeof obj.warrantyMonths !== 'number') errors.push('warrantyMonths: must be a number');
  if (obj.purchaseDate && !isISODate(obj.purchaseDate)) errors.push('purchaseDate: must be ISO 8601 date');
  if (obj.serverRoles && !Array.isArray(obj.serverRoles)) errors.push('serverRoles: must be an array');
  
  return { valid: errors.length === 0, errors };
}

/**
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateRemediation(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['remediation is null or undefined'] };
  
  if (!obj.cve || typeof obj.cve !== 'string') errors.push('cve: required string');
  if (!obj.name || typeof obj.name !== 'string') errors.push('name: required string');
  if (!obj.assets || !Array.isArray(obj.assets)) errors.push('assets: required array');
  if (!obj.status || !['pending','queued','deployed','verified','failed','blocked','rolledBack'].includes(obj.status))
    errors.push(`status: must be pending|queued|deployed|verified|failed|blocked|rolledBack, got "${obj.status}"`);
  if (obj.createdAt && !isISOTimestamp(obj.createdAt)) errors.push('createdAt: must be ISO 8601');
  if (obj.deployedAt && !isISOTimestamp(obj.deployedAt)) errors.push('deployedAt: must be ISO 8601');
  
  return { valid: errors.length === 0, errors };
}

/**
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateVerification(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['verification is null or undefined'] };
  
  // FIXED (Defect #1): was && (AND), should be || (OR) — the old code never caught null findingId
  if (obj.findingId === undefined || obj.findingId === null) errors.push('findingId: required');
  if (!obj.asset || typeof obj.asset !== 'string') errors.push('asset: required string');
  if (!obj.cve || typeof obj.cve !== 'string') errors.push('cve: required string');
  if (!obj.verifiedAt || !isISOTimestamp(obj.verifiedAt)) errors.push('verifiedAt: required ISO 8601 timestamp');
  if (!obj.result || !['pass','fail'].includes(obj.result))
    errors.push(`result: must be pass|fail, got "${obj.result}"`);
  if (!obj.evidence || typeof obj.evidence !== 'string' || obj.evidence.length < 1)
    errors.push('evidence: required non-empty string');
  
  return { valid: errors.length === 0, errors };
}

/**
 * Validate an Exception record.
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateException(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['exception is null or undefined'] };

  if (!obj.id || typeof obj.id !== 'string') errors.push('id: required string');
  if (!obj.cve || typeof obj.cve !== 'string') errors.push('cve: required string');
  if (!obj.asset || typeof obj.asset !== 'string') errors.push('asset: required string');
  if (!obj.type || !['falsePositive','riskAccepted','deferred'].includes(obj.type))
    errors.push(`type: must be falsePositive|riskAccepted|deferred, got "${obj.type}"`);
  if (!obj.reason || typeof obj.reason !== 'string') errors.push('reason: required string');
  if (!obj.approvedBy || typeof obj.approvedBy !== 'string') errors.push('approvedBy: required string');
  if (!obj.createdAt || !isISOTimestamp(obj.createdAt)) errors.push('createdAt: required ISO 8601 timestamp');
  if (!obj.expiresAt || !(isISODate(obj.expiresAt) || isISOTimestamp(obj.expiresAt))) errors.push('expiresAt: required ISO 8601 date (YYYY-MM-DD) or timestamp');
  if (!obj.status || !['active','expired','revoked'].includes(obj.status))
    errors.push(`status: must be active|expired|revoked, got "${obj.status}"`);

  return { valid: errors.length === 0, errors };
}

// ─── Safe Accessors ──────────────────────────────────────────────────────────

/**
 * Read a collection from localStorage with validation.
 * Never throws — returns empty array on any failure.
 * @param {string} key
 * @param {Function} validator — validateRecord(obj) => { valid, errors }
 * @returns {any[]}
 */
export function readCollection(key, validator) {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null || raw === undefined) return [];
    const data = JSON.parse(raw);
    const records = Array.isArray(data) ? data : (data.rows || (data.data || []));
    
    const validRecords = [];
    const invalidCount = { count: 0, reasons: [] };
    
    for (let i = 0; i < records.length; i++) {
      const result = validator(records[i]);
      if (result.valid) {
        validRecords.push(records[i]);
      } else {
        invalidCount.count++;
        if (invalidCount.reasons.length < 5) {
          invalidCount.reasons.push(`Record ${i}: ${result.errors.join('; ')}`);
        }
        console.warn(`[contract] Invalid record in ${key} [${i}]:`, result.errors, records[i]);
      }
    }
    
    if (invalidCount.count > 0) {
      console.warn(`[contract] ${key}: ${invalidCount.count} invalid records skipped (first 5 reasons above)`);
    }
    
    return validRecords;
  } catch (e) {
    console.warn(`[contract] Failed to read ${key}:`, e.message);
    return [];
  }
}

/**
 * Write a collection to localStorage with validation.
 * Never throws — returns result object.
 * @param {string} key
 * @param {any[]} records
 * @param {Function} validator
 * @returns {{ success: boolean, written: number, dropped: number, errors: string[] }}
 */
export function writeCollection(key, records, validator) {
  try {
    if (!Array.isArray(records)) {
      console.warn(`[contract] writeCollection: records must be an array, got ${typeof records}`);
      return { success: false, written: 0, dropped: 0, errors: [`records must be an array, got ${typeof records}`] };
    }
    
    const validRecords = [];
    const invalidCount = { count: 0, reasons: [] };
    
    for (let i = 0; i < records.length; i++) {
      const result = validator(records[i]);
      if (result.valid) {
        validRecords.push(records[i]);
      } else {
        invalidCount.count++;
        if (invalidCount.reasons.length < 5) {
          invalidCount.reasons.push(`Record ${i}: ${result.errors.join('; ')}`);
        }
      }
    }
    
    if (invalidCount.count > 0) {
      console.warn(`[contract] writeCollection ${key}: ${invalidCount.count} records failed validation and were dropped`);
    }

    const serialized = JSON.stringify(validRecords);
    
    localStorage.setItem(key, serialized);
    return {
      success: true,
      written: validRecords.length,
      dropped: invalidCount.count,
      errors: invalidCount.reasons,
    };
  } catch (e) {
    // Handle QuotaExceededError gracefully
    if (e.name === 'QuotaExceededError' || (e.message && e.message.includes('quota'))) {
      console.error(`[contract] writeCollection ${key}: localStorage quota exceeded (${e.message}). Data was NOT saved.`);
      return { success: false, written: 0, dropped: 0, errors: [`QuotaExceededError: ${e.message}`] };
    } else {
      console.warn(`[contract] Failed to write ${key}:`, e.message);
      return { success: false, written: 0, dropped: 0, errors: [e.message] };
    }
  }
}

/**
 * Check localStorage quota and return usage info.
 * Uses the webkit/safari private browsing approach as a fallback.
 * @returns {{ usedBytes: number|null, remainingBytes: number|null, quotaBytes: number|null }}
 */
export function getStorageQuota() {
  try {
    // Modern browsers (Chrome 56+, Firefox 51+)
    if (navigator.storage && navigator.storage.estimate) {
      // navigator.storage.estimate() returns a Promise, so we can't use it
      // synchronously. Return nulls and let callers use getStorageQuotaAsync().
      return { usedBytes: null, remainingBytes: null, quotaBytes: null };
    }

    // Fallback: estimate from total localStorage keys
    let used = 0;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k) used += (k.length + (localStorage.getItem(k) || '').length) * 2; // UTF-16
    }
    const quota = 5 * 1024 * 1024; // Typical 5MB default
    return { usedBytes: used, remainingBytes: Math.max(0, quota - used), quotaBytes: quota };
  } catch (e) {
    return { usedBytes: null, remainingBytes: null, quotaBytes: null };
  }
}

/**
 * Async version of getStorageQuota() using navigator.storage.estimate().
 * @returns {Promise<{ usedBytes: number|null, remainingBytes: number|null, quotaBytes: number|null }>}
 */
export async function getStorageQuotaAsync() {
  try {
    if (navigator.storage && navigator.storage.estimate) {
      const estimate = await navigator.storage.estimate();
      return {
        usedBytes: estimate.usage || 0,
        remainingBytes: Math.max(0, (estimate.quota || 0) - (estimate.usage || 0)),
        quotaBytes: estimate.quota || 0,
      };
    }
    return getStorageQuota(); // fallback to sync version
  } catch (e) {
    return { usedBytes: null, remainingBytes: null, quotaBytes: null };
  }
}

/**
 * Type-safe collection accessors. Use these instead of readCollection(key, validator).
 */
export const FINDINGS = {
  read: () => readCollection(KEYS.IMPORTED_FINDINGS, validateFinding),
  write: (records) => writeCollection(KEYS.IMPORTED_FINDINGS, records, validateFinding),
};

export const ASSETS = {
  read: () => readCollection(KEYS.IMPORTED_ASSETS, validateAsset),
  write: (records) => writeCollection(KEYS.IMPORTED_ASSETS, records, validateAsset),
};

export const REMEDIATIONS = {
  read: () => readCollection(KEYS.REMEDIATION_QUEUE, validateRemediation),
  write: (records) => writeCollection(KEYS.REMEDIATION_QUEUE, records, validateRemediation),
};

export const VERIFICATIONS = {
  read: () => readCollection(KEYS.VALIDATED_REMEDIATIONS, validateVerification),
  write: (records) => writeCollection(KEYS.VALIDATED_REMEDIATIONS, records, validateVerification),
  readQueue: () => readCollection(KEYS.VERIFIED_QUEUE, validateVerification),
  writeQueue: (records) => writeCollection(KEYS.VERIFIED_QUEUE, records, validateVerification),
};

export const EXCEPTIONS = {
  read: () => readCollection(KEYS.EXCEPTIONS, validateException),
  write: (records) => writeCollection(KEYS.EXCEPTIONS, records, validateException),
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isISODate(str) {
  return /^\d{4}-\d{2}-\d{2}$/.test(str);
}

function isISOTimestamp(str) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(str);
}

/**
 * Append an audit entry to a record's auditTrail array.
 * Creates the array if it doesn't exist.
 * @param {Object} record — A Finding, Remediation, or Verification record
 * @param {string} fromState
 * @param {string} toState
 * @param {string} reason
 * @param {string} [source] — "manual" | "remflow" | "thevalidator" | "shieldview"
 */
export function appendAudit(record, fromState, toState, reason, source) {
  if (!record) return;
  if (!fromState || !toState) return; // FIXED (Defect #7): validate state args
  if (!Array.isArray(record.auditTrail)) record.auditTrail = [];
  record.auditTrail.push({
    timestamp: new Date().toISOString(),
    fromState,
    toState,
    reason: reason || 'No reason provided',
    source: source || 'manual',
  });
}

/**
 * Check contract version and show banner on mismatch.
 * Call this once on app startup.
 * @param {string} toolName — Human-readable tool name for the banner
 */
export function checkContractVersion(toolName) {
  try {
    const stored = localStorage.getItem(KEYS.CONTRACT_VERSION_KEY);
    if (!stored) {
      localStorage.setItem(KEYS.CONTRACT_VERSION_KEY, CONTRACT_VERSION);
      return;
    }
    if (stored !== CONTRACT_VERSION) {
      console.warn(`[contract] Version mismatch: ${toolName} has ${CONTRACT_VERSION}, stored is ${stored}`);
      // Render dismissible banner if in browser context
      if (typeof document !== 'undefined' && document.body) { // FIXED (Defect #6): guard document.body
        const banner = document.createElement('div');
        banner.style.cssText = 'background:#352215;color:#ff7722;padding:8px 16px;text-align:center;font-size:12px;font-family:monospace;cursor:pointer';
        banner.textContent = `⚠ Contract version mismatch: ${toolName} v${CONTRACT_VERSION} ≠ stored v${stored}. Some features may not work correctly. Click to dismiss.`;
        banner.onclick = () => { banner.remove(); localStorage.setItem(KEYS.CONTRACT_VERSION_KEY, CONTRACT_VERSION); };
        document.body.prepend(banner);
      }
    }
  } catch (e) {
    // localStorage unavailable — no action needed
  }
}

/**
 * Check if an exception has expired by comparing its expiresAt timestamp
 * against the current time.
 * @param {Object} exception — Exception record with expiresAt ISO timestamp
 * @returns {boolean} true if expired
 */
export function isExceptionExpired(exception) {
  if (!exception || !exception.expiresAt) return false;
  try {
    return new Date(exception.expiresAt).getTime() < Date.now();
  } catch (_) {
    return false;
  }
}

/**
 * Count records by state. Useful for dashboard summaries.
 * @param {Object[]} records — Array of records with a `state` or `status` field
 * @param {string} [field='state'] — The field to group by
 * @returns {Object} state → count mapping, plus a `total` key
 */
export function countByState(records, field) {
  const key = field || 'state';
  const counts = { total: 0 };
  if (!Array.isArray(records)) return counts;
  for (const r of records) {
    counts.total++;
    const val = r[key] || '(none)';
    counts[val] = (counts[val] || 0) + 1;
  }
  return counts;
}
