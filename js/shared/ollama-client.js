/**
 * Ollama Client — Shared Module
 * =============================
 * @version 1.0.0
 *
 * Zero-dependency ES module providing a unified client for Ollama's local API.
 * Shared across RemFlow, TheValidator, AskClippy, and the Launchpad.
 *
 * Supports both /api/chat (OpenAI-compatible) and /api/generate (Ollama native).
 * Default: /api/chat with streaming support.
 */

// ─── Configuration ───────────────────────────────────────────────────────────

const DEFAULT_BASE_URL = 'http://localhost:11434';
const DEFAULT_MODEL = 'llama3.2';
const DEFAULT_TIMEOUT_MS = 60000;

let _baseUrl = DEFAULT_BASE_URL;

/**
 * Override the Ollama base URL (e.g. for proxy or remote Ollama).
 * @param {string} url
 */
export function setBaseUrl(url) {
  _baseUrl = url.replace(/\/+$/, '');
}

/**
 * Get the current base URL.
 * @returns {string}
 */
export function getBaseUrl() {
  return _baseUrl;
}

// ─── Typed Errors ────────────────────────────────────────────────────────────

export class OllamaUnreachableError extends Error {
  constructor(cause) {
    super(cause?.message || 'Ollama is unreachable');
    this.name = 'OllamaUnreachableError';
    this.code = 'UNREACHABLE';
    this.cause = cause;
  }
}

export class ModelMissingError extends Error {
  /**
   * @param {string} model — The model that was requested but not found
   */
  constructor(model) {
    super(`Model "${model}" is not available. Pull it with: ollama pull ${model}`);
    this.name = 'ModelMissingError';
    this.code = 'MODEL_MISSING';
    this.model = model;
  }
}

export class TimeoutError extends Error {
  constructor(timeoutMs) {
    super(`Ollama request timed out after ${timeoutMs}ms`);
    this.name = 'TimeoutError';
    this.code = 'TIMEOUT';
    this.timeoutMs = timeoutMs;
  }
}

export class MalformedResponseError extends Error {
  constructor(detail) {
    super(`Ollama returned a malformed response: ${detail}`);
    this.name = 'MalformedResponseError';
    this.code = 'MALFORMED';
  }
}

// ─── Connection Check ────────────────────────────────────────────────────────

/**
 * Check if Ollama is reachable and list available models.
 * Pings GET /api/tags.
 *
 * @param {Object} [opts]
 * @param {string} [opts.baseUrl] — Override the base URL
 * @param {number} [opts.timeoutMs=3000] — Timeout in ms
 * @returns {Promise<{ok: true, models: string[]} | {ok: false, error: Error}>}
 */
export async function checkConnection(opts = {}) {
  const baseUrl = opts.baseUrl || _baseUrl;
  const timeoutMs = opts.timeoutMs || 3000;

  try {
    const resp = await fetch(`${baseUrl}/api/tags`, {
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) {
      return { ok: false, error: new OllamaUnreachableError(
        new Error(`HTTP ${resp.status}: ${resp.statusText}`)
      )};
    }

    const data = await resp.json();
    const models = (data.models || []).map(m => m.name);

    return { ok: true, models };
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      return { ok: false, error: new TimeoutError(timeoutMs) };
    }
    if (err instanceof TypeError && err.message.includes('fetch')) {
      return { ok: false, error: new OllamaUnreachableError(err) };
    }
    return { ok: false, error: new OllamaUnreachableError(err) };
  }
}

/**
 * List available model names. Shortcut for checkConnection() → models.
 *
 * @param {Object} [opts]
 * @returns {Promise<string[]>}
 */
export async function listModels(opts = {}) {
  const result = await checkConnection(opts);
  if (!result.ok) throw result.error;
  return result.models;
}

// ─── Streaming Completion (Chat API) ─────────────────────────────────────────

/**
 * Stream a chat completion from Ollama using the /api/chat endpoint.
 * Calls onToken for each chunk, onDone when complete, onError on failure.
 *
 * @param {Object} params
 * @param {string} params.model — Model name (e.g. 'llama3.2')
 * @param {string} params.prompt — User message content
 * @param {string} [params.systemPrompt] — System prompt (role: system)
 * @param {Object} params.callbacks
 * @param {(token: string) => void} params.callbacks.onToken — Called for each text chunk
 * @param {(fullText: string) => void} params.callbacks.onDone — Called on successful completion
 * @param {(error: Error) => void} params.callbacks.onError — Called on any error
 * @param {AbortSignal} [params.signal] — AbortSignal for cancellation
 * @param {Object} [params.options] — Ollama model options (temperature, num_predict, etc.)
 * @param {string} [params.baseUrl] — Override the base URL
 */
export async function streamCompletion({
  model = DEFAULT_MODEL,
  prompt,
  systemPrompt,
  callbacks,
  signal,
  options = {},
  baseUrl,
}) {
  const { onToken, onDone, onError } = callbacks;
  const url = baseUrl || _baseUrl;

  if (!prompt || typeof prompt !== 'string') {
    onError(new MalformedResponseError('prompt is required and must be a string'));
    return;
  }

  const messages = [];
  if (systemPrompt) {
    messages.push({ role: 'system', content: systemPrompt });
  }
  messages.push({ role: 'user', content: prompt });

  try {
    const resp = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: true,
        options: {
          temperature: 0.3,
          num_predict: 2048,
          ...options,
        },
      }),
      signal,
    });

    if (!resp.ok) {
      const errorBody = await resp.text().catch(() => '');
      throw new OllamaUnreachableError(
        new Error(`HTTP ${resp.status}: ${resp.statusText}${errorBody ? ' — ' + errorBody : ''}`)
      );
    }

    if (!resp.body) {
      throw new MalformedResponseError('Response body is null — streaming not supported');
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let fullText = '';
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // Ollama streams one JSON object per line (NDJSON)
      const lines = buffer.split('\n');
      // Keep the last partial line in the buffer
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        try {
          const chunk = JSON.parse(trimmed);
          if (chunk.message?.content) {
            fullText += chunk.message.content;
            onToken(chunk.message.content);
          }
          if (chunk.done === true) {
            onDone(fullText);
            return;
          }
        } catch (parseErr) {
          // Skip malformed JSON lines — they happen with large chunks
          console.warn('[ollama-client] Skipping unparseable chunk:', trimmed.slice(0, 80));
        }
      }
    }

    // If we reach here without an explicit done signal, treat buffer as final
    if (buffer.trim()) {
      try {
        const finalChunk = JSON.parse(buffer.trim());
        if (finalChunk.message?.content) {
          fullText += finalChunk.message.content;
          onToken(finalChunk.message.content);
        }
      } catch (_) { /* ignore */ }
    }

    onDone(fullText);
  } catch (err) {
    if (err.name === 'OllamaUnreachableError' || err.name === 'MalformedResponseError') {
      onError(err);
    } else if (err.name === 'AbortError' || (signal && signal.aborted)) {
      onError(new TimeoutError(DEFAULT_TIMEOUT_MS));
    } else if (err instanceof TypeError && err.message.includes('fetch')) {
      onError(new OllamaUnreachableError(err));
    } else {
      onError(new OllamaUnreachableError(err));
    }
  }
}

// ─── Non-Streaming Completion (Chat API) ─────────────────────────────────────

/**
 * Get a non-streaming chat completion from Ollama.
 *
 * @param {Object} params
 * @param {string} params.model — Model name
 * @param {string} params.prompt — User message
 * @param {string} [params.systemPrompt] — System prompt
 * @param {AbortSignal} [params.signal] — AbortSignal
 * @param {Object} [params.options] — Ollama model options
 * @param {number} [params.timeoutMs=60000] — Timeout in ms
 * @param {string} [params.baseUrl] — Override base URL
 * @returns {Promise<string>} The assistant's response text
 */
export async function chatCompletion({
  model = DEFAULT_MODEL,
  prompt,
  systemPrompt,
  signal,
  options = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
  baseUrl,
}) {
  const url = baseUrl || _baseUrl;

  if (!prompt || typeof prompt !== 'string') {
    throw new MalformedResponseError('prompt is required and must be a string');
  }

  const messages = [];
  if (systemPrompt) {
    messages.push({ role: 'system', content: systemPrompt });
  }
  messages.push({ role: 'user', content: prompt });

  // Merge timeout with any external signal
  let effectiveSignal = signal;
  if (!effectiveSignal) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    effectiveSignal = controller.signal;
    // Clean up the timeout on completion
    const cleanup = () => clearTimeout(timeoutId);
    effectiveSignal._cleanup = cleanup;
  }

  try {
    const resp = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        options: {
          temperature: 0.3,
          num_predict: 2048,
          ...options,
        },
      }),
      signal: effectiveSignal,
    });

    if (effectiveSignal._cleanup) effectiveSignal._cleanup();

    if (!resp.ok) {
      const errorBody = await resp.text().catch(() => '');
      throw new OllamaUnreachableError(
        new Error(`HTTP ${resp.status}: ${resp.statusText}${errorBody ? ' — ' + errorBody : ''}`)
      );
    }

    const data = await resp.json();
    const content = data.message?.content || data.response;

    if (content === undefined || content === null) {
      throw new MalformedResponseError(
        `No content in response. Keys: ${Object.keys(data).join(', ')}`
      );
    }

    return content;
  } catch (err) {
    if (effectiveSignal._cleanup) effectiveSignal._cleanup();

    if (err.name === 'OllamaUnreachableError' || err.name === 'MalformedResponseError') {
      throw err;
    }
    if (err.name === 'AbortError' || err.name === 'TimeoutError') {
      throw new TimeoutError(timeoutMs);
    }
    if (err instanceof TypeError && err.message.includes('fetch')) {
      throw new OllamaUnreachableError(err);
    }
    throw new OllamaUnreachableError(err);
  }
}

// ─── Legacy Compatibility Wrappers ────────────────────────────────────────────

/**
 * Simple call-and-response — matches the old RemFlow callOllama(systemPrompt, userPrompt) signature.
 * @deprecated Use chatCompletion() for new code.
 *
 * @param {string} systemPrompt
 * @param {string} userPrompt
 * @param {Object} [opts]
 * @param {string} [opts.model]
 * @param {AbortSignal} [opts.signal]
 * @returns {Promise<string>}
 */
export async function callOllama(systemPrompt, userPrompt, opts = {}) {
  return chatCompletion({
    model: opts.model || DEFAULT_MODEL,
    prompt: userPrompt,
    systemPrompt,
    signal: opts.signal,
    timeoutMs: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
  });
}

/**
 * Generate completion using the Ollama native /api/generate endpoint.
 * @deprecated Prefer chatCompletion() for new code. This is for TheValidator compatibility.
 *
 * @param {string} prompt — Full prompt string (no separate system/user roles)
 * @param {Object} [opts]
 * @param {string} [opts.model]
 * @param {AbortSignal} [opts.signal]
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<string>}
 */
export async function generateCompletion(prompt, opts = {}) {
  const url = opts.baseUrl || _baseUrl;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;

  let effectiveSignal = opts.signal;
  if (!effectiveSignal) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    effectiveSignal = controller.signal;
    effectiveSignal._cleanup = () => clearTimeout(timeoutId);
  }

  try {
    const resp = await fetch(`${url}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: opts.model || DEFAULT_MODEL,
        prompt,
        stream: false,
        options: {
          temperature: 0.7,
          num_predict: 1024,
          ...opts.options,
        },
      }),
      signal: effectiveSignal,
    });

    if (effectiveSignal._cleanup) effectiveSignal._cleanup();

    if (!resp.ok) {
      throw new OllamaUnreachableError(new Error(`HTTP ${resp.status}`));
    }

    const data = await resp.json();
    return data.response || '';
  } catch (err) {
    if (effectiveSignal._cleanup) effectiveSignal._cleanup();

    if (err.name === 'AbortError') {
      throw new TimeoutError(timeoutMs);
    }
    if (err instanceof TypeError && err.message.includes('fetch')) {
      throw new OllamaUnreachableError(err);
    }
    throw err;
  }
}

// ─── Health Check Helper ─────────────────────────────────────────────────────

/**
 * Quick availability check. Returns boolean.
 * @param {Object} [opts]
 * @returns {Promise<boolean>}
 */
export async function isAvailable(opts = {}) {
  const result = await checkConnection({ timeoutMs: opts.timeoutMs || 2000, ...opts });
  return result.ok;
}
