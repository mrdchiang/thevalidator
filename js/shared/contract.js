/**
 * Security Tools Suite — Shared Data Contract
 * =============================================
 * @version 1.0.0
 * 
 * Zero-dependency ES module defining the localStorage contract between
 * ShieldView, RemFlow, TheValidator, AskClippy, and the Launchpad.
 * 
 * All five apps are subpaths of the same origin (mrdchiang.github.io),
 * so they share one localStorage namespace. This module is the single
 * source of truth for every key, record shape, and access pattern.
 *
 * CONVENTIONS:
 * - All timestamps are ISO 8601 with timezone (e.g. "2026-07-24T20:45:00Z")
 * - All state transitions append to an audit trail, never overwrite history
 * - Accessors never throw on malformed data — they degrade visibly
 * - Every key is namespaced under "security-tools:"
 */

// ─── Version ────────────────────────────────────────────────────────────────
export const CONTRACT_VERSION = '1.0.0';

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
 * @property {string} state — "Active" | "Fixed" | "Actioned" | "Risk Accepted" | "False Positive" | "Deferred"
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
 * @property {string} [auditTrail[].source] — "manual" | "remflow" | "thevalidator"
 */

/**
 * @typedef {Object} Asset
 * @property {string} hostname — Primary key, matched case-insensitively
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
  if (!obj.state || !['Active','Fixed','Actioned','Risk Accepted','False Positive','Deferred'].includes(obj.state))
    errors.push(`state: must be Active|Fixed|Actioned|Risk Accepted|False Positive|Deferred, got "${obj.state}"`);
  if (obj.firstSeen && !isISODate(obj.firstSeen)) errors.push('firstSeen: must be ISO 8601 date (YYYY-MM-DD)');
  if (obj.dueDate && !isISODate(obj.dueDate)) errors.push('dueDate: must be ISO 8601 date (YYYY-MM-DD)');
  if (obj.fixedAt && !isISOTimestamp(obj.fixedAt)) errors.push('fixedAt: must be ISO 8601 timestamp');
  if (obj.verifiedAt && !isISOTimestamp(obj.verifiedAt)) errors.push('verifiedAt: must be ISO 8601 timestamp');
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
  if (!obj.assets || !Array.isArray(obj.assets)) errors.push('assets: required array');
  if (!obj.status || !['pending','queued','deployed','failed','blocked'].includes(obj.status))
    errors.push(`status: must be pending|queued|deployed|failed|blocked, got "${obj.status}"`);
  if (obj.createdAt && !isISOTimestamp(obj.createdAt)) errors.push('createdAt: must be ISO 8601');
  
  return { valid: errors.length === 0, errors };
}

/**
 * @param {Object} obj
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateVerification(obj) {
  const errors = [];
  if (!obj) return { valid: false, errors: ['verification is null or undefined'] };
  
  if (obj.findingId === undefined && obj.findingId === null) errors.push('findingId: required');
  if (!obj.asset || typeof obj.asset !== 'string') errors.push('asset: required string');
  if (!obj.cve || typeof obj.cve !== 'string') errors.push('cve: required string');
  if (!obj.verifiedAt || !isISOTimestamp(obj.verifiedAt)) errors.push('verifiedAt: required ISO 8601 timestamp');
  if (!obj.result || !['pass','fail'].includes(obj.result))
    errors.push(`result: must be pass|fail, got "${obj.result}"`);
  if (!obj.evidence || typeof obj.evidence !== 'string' || obj.evidence.length < 1)
    errors.push('evidence: required non-empty string');
  
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
    const records = Array.isArray(data) ? data : (data.rows || []);
    
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
 * Never throws — returns success boolean.
 * @param {string} key
 * @param {any[]} records
 * @param {Function} validator
 * @returns {boolean}
 */
export function writeCollection(key, records, validator) {
  try {
    if (!Array.isArray(records)) {
      console.warn(`[contract] writeCollection: records must be an array, got ${typeof records}`);
      return false;
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
    
    localStorage.setItem(key, JSON.stringify(validRecords));
    return true;
  } catch (e) {
    console.warn(`[contract] Failed to write ${key}:`, e.message);
    return false;
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
 * @param {string} [source] — "manual" | "remflow" | "thevalidator"
 */
export function appendAudit(record, fromState, toState, reason, source) {
  if (!record) return;
  if (!Array.isArray(record.auditTrail)) record.auditTrail = [];
  record.auditTrail.push({
    timestamp: new Date().toISOString(),
    fromState,
    toState,
    reason,
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
      if (typeof document !== 'undefined') {
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
