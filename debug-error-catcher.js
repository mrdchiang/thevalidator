// ===== Error Catcher & Debug Log (v1.0) =====
// Captures runtime errors and stores them for debug.html review
// Insert this at the top of <script> in index.html (or load via <script src>)
(function() {
  'use strict';

  const STORAGE_KEY = 'security-tools:error-log';
  const MAX_ERRORS = 200;
  const TOOL_NAME = document.title || location.pathname.split('/').filter(Boolean).pop() || 'Unknown';

  function getLog() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
    catch(e) { return []; }
  }

  function saveLog(log) {
    try {
      // Keep only the most recent MAX_ERRORS
      while (log.length > MAX_ERRORS) log.shift();
      localStorage.setItem(STORAGE_KEY, JSON.stringify(log));
    } catch(e) {
      // localStorage might be full — trim harder
      try {
        while (log.length > 50) log.shift();
        localStorage.setItem(STORAGE_KEY, JSON.stringify(log));
      } catch(e2) {}
    }
  }

  function addEntry(entry) {
    entry.tool = TOOL_NAME;
    entry.url = location.href;
    entry.timestamp = new Date().toISOString();
    entry.userAgent = navigator.userAgent;
    const log = getLog();
    log.push(entry);
    saveLog(log);
  }

  // Catch unhandled JS errors
  window.onerror = function(message, source, lineno, colno, error) {
    addEntry({
      type: 'runtime-error',
      message: String(message),
      source: source || '',
      line: lineno || 0,
      col: colno || 0,
      stack: error && error.stack ? String(error.stack).slice(0, 2000) : ''
    });
    // Don't prevent default browser error handling
    return false;
  };

  // Catch unhandled Promise rejections
  window.addEventListener('unhandledrejection', function(event) {
    const reason = event.reason;
    addEntry({
      type: 'unhandled-rejection',
      message: String(reason),
      stack: reason && reason.stack ? String(reason.stack).slice(0, 2000) : ''
    });
  });

  // Catch console.error calls
  var origConsoleError = console.error;
  console.error = function() {
    try {
      var args = Array.prototype.slice.call(arguments);
      var msg = args.map(function(a) {
        try {
          return typeof a === 'object' ? JSON.stringify(a, null, 2).slice(0, 500) : String(a);
        } catch(e) { return String(a); }
      }).join(' ');
      addEntry({
        type: 'console-error',
        message: msg.slice(0, 2000),
        args: args.length
      });
    } catch(e) {}
    // Call original
    return origConsoleError.apply(console, arguments);
  };

  // Expose a helper for manual error logging
  window.__debugLog = function(message, data) {
    addEntry({
      type: 'manual',
      message: String(message),
      data: data ? JSON.stringify(data).slice(0, 1000) : ''
    });
  };

  console.log('[' + TOOL_NAME + '] Error catcher active ✓');
})();
