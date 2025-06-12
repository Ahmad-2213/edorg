import { connect } from 'cloudflare:sockets'

/**
 * Default settings.
 */
const SETTINGS = {
  UUID: '', // vless UUID
  PROXY: '87.128.18.23', // optional proxy hostname or IP
  LOG_LEVEL: 'debug', // debug, info, error, none
  TIME_ZONE: '0', // time zone for logs (in hours)
  
  WS_PATH: '/ws', // path for websocket transport (enable by non‑empty string)
  DOH_QUERY_PATH: '/dns-query', // path for DNS over HTTPS queries
  UPSTREAM_DOH: 'https://dns.google/dns-query',
  IP_QUERY_PATH: '',

  BUFFER_SIZE: '0', // in KiB; setting to '0' means no explicit buffering (workers CPU load is mitigated by native stream passthrough)
  XHTTP_PATH: '/xhttp',
  XPADDING_RANGE: '0',

  // We now use only the pipe relay so that we delegate most work to pipeTo().
  RELAY_SCHEDULER: 'pipe',

};



// A constant response for bad requests.
const BAD_REQUEST = new Response(null, {
  status: 404,
  statusText: 'Bad Request',
});

/* ─────────────────────────────────────────────────────────────────────────────
   Utility Functions
   ───────────────────────────────────────────────────────────────────────────── */

   function validate_uuid(received, expected) {
    return crypto.subtle.timingSafeEqual(received, expected);
  }

function concat_typed_arrays(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function random_num(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function random_id() {
  const min = 10000, max = 99999;
  return random_num(min, max);
}

function random_str(len) {
  return Array.from({ length: len }, () => ((Math.random() * 36) | 0).toString(36)).join('');
}

function random_uuid() {
  const s4 = () =>
    Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  return `${s4()}${s4()}-${s4()}-${s4()}-${s4()}-${s4()}${s4()}${s4()}`;
}

const MAX_PADDING_LENGTH = 1000;

function random_padding(range_str) {
  if (!range_str || range_str === '0' || typeof range_str !== 'string') return null;
  const range = range_str
    .split('-')
    .map(s => parseInt(s, 10))
    .filter(n => !isNaN(n))
    .slice(0, 2)
    .sort((a, b) => a - b);
  if (range.length === 0 || range[0] < 1) return null;
  let len = range[0] === range[1] ? range[0] : random_num(range[0], range[1]);
  len = Math.min(len, MAX_PADDING_LENGTH);
  return '0'.repeat(len);
}

function parse_uuid(uuid) {
  const bytes = new Uint8Array(16);
  let byteIndex = 0, haveNibble = false, nibble = 0;
  for (let i = 0, len = uuid.length; i < len && byteIndex < 16; i++) {
    const code = uuid.charCodeAt(i);
    if (code === 45) continue; // Skip '-' (ASCII 45)
    let value;
    // '0'-'9'
    if (code >= 48 && code <= 57) {
      value = code - 48;
    }
    // 'A'-'F'
    else if (code >= 65 && code <= 70) {
      value = code - 55;
    }
    // 'a'-'f'
    else if (code >= 97 && code <= 102) {
      value = code - 87;
    } else {
      throw new Error('Invalid UUID character');
    }
    if (!haveNibble) {
      nibble = value;
      haveNibble = true;
    } else {
      bytes[byteIndex++] = (nibble << 4) | value;
      haveNibble = false;
    }
  }
  return bytes;
}

/**
 * Decodes a modified Base64 string (URL‑friendly, using "-" and "_" instead of "+" and "/")
 * into an ArrayBuffer. Returns null on failure.
 */
function base64ToArrayBuffer(base64Str) {
  try {
    // Replace without regex:
    base64Str = base64Str.split('-').join('+').split('_').join('/');
    const binaryStr = atob(base64Str);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (err) {
    return null;
  }
}


/* ─────────────────────────────────────────────────────────────────────────────
   Logger
   ───────────────────────────────────────────────────────────────────────────── */

class Logger {
  constructor(log_level, time_zone) {
    this.inner_id = random_id();
    const tz = parseInt(time_zone);
    this.timeDrift = isNaN(tz) ? 0 : tz * 60 * 60 * 1000;
    const levels = ['debug', 'info', 'error', 'none'];
    this.level = levels.indexOf((log_level || 'info').toLowerCase());
  }
  debug(...args) {
    if (this.level <= 0) this.inner_log('DEBUG', ...args);
  }
  info(...args) {
    if (this.level <= 1) this.inner_log('INFO', ...args);
  }
  error(...args) {
    if (this.level <= 2) this.inner_log('ERROR', ...args);
  }
  inner_log(prefix, ...args) {
    const now = new Date(Date.now() + this.timeDrift).toISOString();
    console.log(now, prefix, `(${this.inner_id})`, ...args);
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Reading and Parsing VLESS Header
   ───────────────────────────────────────────────────────────────────────────── */

async function read_vless_header(reader, cfg_uuid_str) {
  let capacity = 8192;
  let buffer = new Uint8Array(capacity);
  let offset = 0;
  const view = new DataView(buffer.buffer);
  
  async function ensureAvailable(n) {
    while (offset < n) {
      const { value, done } = await reader.read();
      if (done) throw new Error('header length too short');
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      if (offset + chunk.length > capacity) {
        capacity = Math.max(capacity * 2, offset + chunk.length);
        const newBuffer = new Uint8Array(capacity);
        newBuffer.set(buffer);
        buffer = newBuffer;
      }
      buffer.set(chunk, offset);
      offset += chunk.length;
    }
  }

  await ensureAvailable(1 + 16 + 1);
  const version = view.getUint8(0);
  const uuid = buffer.subarray(1, 17);
  const cfg_uuid = parse_uuid(cfg_uuid_str);
  if (!validate_uuid(uuid, cfg_uuid)) throw new Error('invalid UUID');

  const pb_len = buffer[17];
  const addr_plus1 = 18 + pb_len + 1 + 2 + 1;
  await ensureAvailable(addr_plus1 + 1);

  const cmd = buffer[18 + pb_len];
  if (cmd !== 1) throw new Error(`unsupported command: ${cmd}`);

  const port = (buffer[addr_plus1 - 3] << 8) | buffer[addr_plus1 - 2];
  const atype = buffer[addr_plus1 - 1];
  let header_len = -1;
  if (atype === 1) header_len = addr_plus1 + 4;
  else if (atype === 3) header_len = addr_plus1 + 16;
  else if (atype === 2) {
    await ensureAvailable(addr_plus1 + 1);
    header_len = addr_plus1 + 1 + buffer[addr_plus1];
  }
  if (header_len < 0) throw new Error('read address type failed');
  await ensureAvailable(header_len);

  let hostname = '';
  const idx = addr_plus1;
  if (atype === 1) {
    hostname = `${buffer[idx]}.${buffer[idx + 1]}.${buffer[idx + 2]}.${buffer[idx + 3]}`;
  } else if (atype === 2) {
    hostname = new TextDecoder().decode(buffer.subarray(idx + 1, idx + 1 + buffer[idx]));
  } else if (atype === 3) {
    hostname = Array.from(buffer.subarray(idx, idx + 16), byte => byte.toString(16).padStart(2, '0')).join(':');
  }
  if (!hostname) throw new Error('parse hostname failed');

  return {
    hostname,
    port,
    data: buffer.subarray(header_len, offset),
    resp: new Uint8Array([version, 0]),
  };
}

async function parse_header(uuid_str, client) {
  const reader = client.readable.getReader();
  try {
    return await read_vless_header(reader, uuid_str);
  } finally {
    reader.releaseLock();
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Connecting and Relaying
   ───────────────────────────────────────────────────────────────────────────── */

async function pipeRelay(src, dest, initialData) {
  if (initialData && initialData.byteLength > 0) {
    const writer = dest.writable.getWriter();
    try {
      await writer.write(initialData);
    } finally {
      writer.releaseLock();
    }
  }
  const options = src.signal ? { signal: src.signal } : {};
  return src.readable.pipeTo(dest.writable, options);
}

async function relayConnections( log, client, remote, vless) {
  const upload = pipeRelay(client, remote, vless.data).catch(err => {
    if (err.name !== 'AbortError') log.error("Upload error:", err.message);
  });
  const download = pipeRelay(remote, client, vless.resp).catch(err => {
    if (err.name !== 'AbortError') log.error("Download error:", err.message);
  });
  await Promise.all([upload, download])
    .then(() => log.info("Connection closed."))
    .catch(err => log.error("Relay encountered an error:", err.message));
}

function watch_abort_signal(log, signal, remote) {
  if (!signal || !remote) return;
  const handler = () => {
    log.debug("Aborted, closing remote connection.");
    remote.close().catch(err => log.error("Error closing remote:", err));
    signal.removeEventListener('abort', handler);
  };
  if (signal.aborted) return handler();
  signal.addEventListener('abort', handler, { once: true });
}

async function timed_connect(hostname, port, ms) {
  return new Promise((resolve, reject) => {
    const conn = connect({ hostname, port });
    const timeoutId = setTimeout(() => reject(new Error("connect timeout")), ms);
    conn.opened.then(() => {
      clearTimeout(timeoutId);
      resolve(conn);
    }).catch(err => {
      clearTimeout(timeoutId);
      reject(err);
    });
  });
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

let connectionHistory = {};
const DIRECT_SUCCESS_COOL_DOWN = 30000; // 30 seconds

function recordDirectSuccess(hostname) {
  connectionHistory[hostname] = Date.now();
}

function directRecently(hostname) {
  return connectionHistory[hostname] && (Date.now() - connectionHistory[hostname] < DIRECT_SUCCESS_COOL_DOWN);
}

function isEpicGamesDomain(hostname) {
  return /(?:epicgames\.com|epicgamescdn\.com|riotgames\.com|api\.riotgames\.com|ddragon\.leagueoflegends\.com|riotstatic\.com|riotcdn\.net|akamaized\.net|fastly-download\.epicgames\.com|clashofclans\.com|ubisoft(?:connect)?\.com|ubisoftcdn\.com|uplay(?:cdn)?\.com|supercell(?:content)?\.net|d\d+\.[a-z0-9-]+\.cloudfront\.net)/i.test(hostname);
}

const proxyFailureBlacklist = {};
function markProxyForbidden(hostname) {
  proxyFailureBlacklist[hostname] = true;
}

/**
 * Returns true if `ip` is a valid IPv4 or IPv6 address literal.
 */
function isIPAddress(ip) {
  // --- IPv4 check ---
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (const part of parts) {
      // no leading zeros (unless the part is exactly "0")
      if (!/^\d+$/.test(part) || (part.length > 1 && part.startsWith('0'))) return false;
      const n = Number(part);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }

  // --- IPv6 check ---
  if (ip.includes(':')) {
    // Split on '::' for compressed zeros
    const comps = ip.split('::');
    if (comps.length > 2) return false;

    // parts before and after '::'
    const head = comps[0] === '' ? [] : comps[0].split(':');
    const tail = comps[1] ? comps[1].split(':') : [];

    // total hextets must be <= 8
    if (head.length + tail.length > 8) return false;

    const validHextet = s =>
      /^[0-9A-Fa-f]{1,4}$/.test(s);

    for (const seg of [...head, ...tail]) {
      if (!validHextet(seg)) return false;
    }

    return true;
  }

  // neither IPv4 nor IPv6
  return false;
}



async function connect_remote(log, hostname, port, cfg_proxy) {
  const timeout = 1000
  
 
  if (isIPAddress(hostname)) {
    try {
        log.info(`direct connect to IP [${hostname}]:${port}`)
        return await timed_connect(hostname, port, timeout)
    } catch (err) {
        log.error(`direct connect to IP failed: ${err.message}`)
    }
    
}
  const proxy = (cfg_proxy)
  if (proxy) {
      try {
        log.info(`proxy connect [${hostname}]:${port} through [${proxy}]`)
        return await timed_connect(proxy, port, timeout)
      } catch (err) {
        log.debug(`proxy connect failed: ${err.message}`)
      }
      
    } 

  throw new Error('all connection attempts failed')
}
async function handle_client(cfg, log, client) {
  try {
    const vless = await parse_header(cfg.UUID, client);
    const remote = await connect_remote(log, vless.hostname, vless.port, cfg.PROXY);
    relayConnections( log, client, remote, vless);
    watch_abort_signal(log, client.signal, remote);
    return true;
  } catch (err) {
    log.error("handle_client error:", err.message);
    client.close && client.close();
    return false;
  }
}



/* ─────────────────────────────────────────────────────────────────────────────
   XHTTP and WebSocket Client Factories
   ───────────────────────────────────────────────────────────────────────────── */

/**
 * Create a queuing strategy with the given buff_size (in bytes).
 */
function create_queuing_strategy(buff_size) {
  return new ByteLengthQueuingStrategy({ highWaterMark: buff_size });
}

/**
 * Create an XHTTP client.
 * 
 * Modified for stream-one: Instead of using an explicit transform function,
 * we use the default identity transformer by omitting a transformer argument.
 * This lets the platform handle chunk transfer natively, reducing per-chunk JS overhead.
 */
function create_xhttp_client(cfg, client_readable) {
  const transformStream = new TransformStream(undefined);

  const headers = {
    'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
    'content-type': 'application/grpc',
  };

  const padding = random_padding(cfg.XPADDING_RANGE);
  if (padding) headers['X-Padding'] = padding;

  const resp = new Response(transformStream.readable, { headers });
  return {
    readable: client_readable,
    writable: transformStream.writable,
    resp,
    close: () => {
      try {
        const writer = transformStream.writable.getWriter();
        writer.close().catch(() => {});
      } catch (e) {}
    }
  };
}
function safeCloseWebSocket(ws, log) {
  if (!ws || ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
    return;
  }
  try {
    ws.close();
  } catch (err) {
    log.error("Error closing WebSocket:", err);
  }
}
function makeWebSocketStreams(ws, earlyData, log) {
  

  const readable = new ReadableStream({
    start(controller) {
      // Enqueue early data if provided.
      if (earlyData) {
        try {
          const earlyBuffer = base64ToArrayBuffer(earlyData);
          if (earlyBuffer) {
            log.info("Enqueuing early data", earlyBuffer.byteLength);
            controller.enqueue(earlyBuffer);
          }
        } catch (err) {
          log.error("Failed to decode early data", err);
        }
      }
      ws.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      ws.addEventListener("error", (err) => {
        log.error("WebSocket server error", err);
        controller.error(err);
      });
      ws.addEventListener("close", () => {
        log.info("WebSocket server closed");
        controller.close();
      });
    }
  });

  const writable = new WritableStream({
    write(chunk) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(chunk);
      }
    }
  });

  return { readable, writable };
}


function create_ws_client(log, ws_client, ws_server, earlyData) {
  const abort_ctrl = new AbortController();
  let wsClosed = false;

  function close() {
    if (!wsClosed) {
      wsClosed = true;
      safeCloseWebSocket(ws_server, log);
      abort_ctrl.abort();
    }
  }

  const { readable, writable } = makeWebSocketStreams(ws_server, earlyData, log);

  ws_server.accept();
   

  return {
    readable,
    writable,
    resp: new Response(null, { status: 101, webSocket: ws_client }),
    signal: abort_ctrl.signal,
    close,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Handling DoH and JSON Requests
   ───────────────────────────────────────────────────────────────────────────── */

function handle_doh(log, request, url, upstream) {
  const mime_dnsmsg = 'application/dns-message';
  const method = request.method;
  if (method === 'POST' && request.headers.get('content-type') === mime_dnsmsg) {
    log.info("handle DoH POST request");
    return fetch(upstream, {
      method,
      headers: {
        Accept: mime_dnsmsg,
        'Content-Type': mime_dnsmsg,
      },
      body: request.body,
    });
  }
  if (method !== 'GET') return BAD_REQUEST;
  const mime_json = 'application/dns-json';
  if (request.headers.get('Accept') === mime_json) {
    log.info("handle DoH GET json request");
    return fetch(upstream + url.search, {
      method,
      headers: { Accept: mime_json },
    });
  }
  const param = url.searchParams.get('dns');
  if (param) {
    log.info("handle DoH GET hex request");
    return fetch(upstream + '?dns=' + param, {
      method,
      headers: { Accept: mime_dnsmsg },
    });
  }
  return BAD_REQUEST;
}

function get_ip_info(request) {
  return {
    ip: request.headers.get('cf-connecting-ip') || '',
    userAgent: request.headers.get('user-agent') || '',
    asOrganization: request.cf?.asOrganization || '',
    city: request.cf?.city || '',
    continent: request.cf?.continent || '',
    country: request.cf?.country || '',
    latitude: request.cf?.latitude || '',
    longitude: request.cf?.longitude || '',
    region: request.cf?.region || '',
    regionCode: request.cf?.regionCode || '',
    timezone: request.cf?.timezone || '',
  };
}

function handle_json(cfg, url, request) {
  if (cfg.IP_QUERY_PATH && request.url.endsWith(cfg.IP_QUERY_PATH)) {
    return get_ip_info(request);
  }
  const path = append_slash(url.pathname);
  if (url.searchParams.get('uuid') === cfg.UUID) {
    if (cfg.XHTTP_PATH && path.endsWith(cfg.XHTTP_PATH)) {
      return create_config('xhttp', url, cfg.UUID);
    }
    if (cfg.WS_PATH && path.endsWith(cfg.WS_PATH)) {
      return create_config('ws', url, cfg.UUID);
    }
  }
  return null;
}

function append_slash(path) {
  return path.endsWith('/') ? path : path + '/';
}

function create_config(ctype, url, uuid) {
  const config = JSON.parse(JSON.stringify(config_template));
  const vless = config.outbounds[0].settings.vnext[0];
  const stream = config.outbounds[0].streamSettings;
  const host = url.hostname;
  vless.users[0].id = uuid;
  vless.address = host;
  stream.tlsSettings.serverName = host;
  const path = append_slash(url.pathname);
  if (ctype === 'ws') {
    delete stream.tlsSettings.alpn;
    stream.wsSettings = { path, host };
  } else if (ctype === 'xhttp') {
    stream.xhttpSettings = {
      mode: 'stream-one',
      host,
      path,
      noGRPCHeader: false,
      keepAlivePeriod: 300,
    };
  } else {
    return null;
  }
  if (url.searchParams.get('fragment') === 'true') {
    config.outbounds[0].proxySettings = {
      tag: 'direct',
      transportLayer: true,
    };
    config.outbounds.push({
      tag: 'direct',
      protocol: 'freedom',
      settings: {
        fragment: {
          packets: 'tlshello',
          length: '100-200',
          interval: '10-20',
        },
      },
    });
  }
  stream.network = ctype;
  return config;
}

const config_template = {
  log: { loglevel: "warning" },
  inbounds: [
    {
      tag: "agentin",
      port: 1080,
      listen: "127.0.0.1",
      protocol: "socks",
      settings: {}
    }
  ],
  outbounds: [
    {
      protocol: "vless",
      settings: {
        vnext: [
          {
            address: "localhost",
            port: 443,
            users: [
              { id: "", encryption: "none" }
            ]
          }
        ]
      },
      tag: "agentout",
      streamSettings: {
        network: "raw",
        security: "tls",
        tlsSettings: {
          serverName: "localhost",
          alpn: [ "h2" ]
        }
      }
    }
  ]
};

function example(url) {
  const ws_path = random_str(8);
  const xhttp_path = random_str(8);
  const uuid = random_uuid();
  return `Error: UUID is empty

Settings example:
UUID: ${uuid}
WS_PATH: /${ws_path}
XHTTP_PATH: /${xhttp_path}

WebSocket config.json:
${url.origin}/${ws_path}/?fragment=true&uuid=${uuid}

XHTTP config.json:
${url.origin}/${xhttp_path}/?fragment=true&uuid=${uuid}

Refresh this page to re‑generate a random settings example.`;
}



function isValidIP(ip) {
  return isIPAddress(ip);
}

/* ─────────────────────────────────────────────────────────────────────────────
   Main Request Handler
   ───────────────────────────────────────────────────────────────────────────── */

async function main(request, env, ctx) {
  const url = new URL(request.url);

  let proxyIP = '';
  const pathParts = url.pathname.split('/').filter(p => p.length > 0);
  if (pathParts.length === 2 && isValidIP(pathParts[1])) {
    proxyIP = pathParts[1];
    url.pathname = `/${pathParts[0]}/`;
  }

  const cfg = load_settings(env, SETTINGS);
  if (proxyIP) {
    cfg.PROXY = proxyIP;
  }
  const log = new Logger(cfg.LOG_LEVEL, cfg.TIME_ZONE);
  if (proxyIP) {
    log.info(`Using proxy IP from URL path: ${cfg.PROXY}`);
  }

  if (!cfg.UUID) {
    return new Response(example(url));
  }

  let buff_size = (parseInt(cfg.BUFFER_SIZE, 10) || 0) * 1024;

  if (cfg.WS_PATH &&
    request.headers.get('Upgrade') === 'websocket' &&
    url.pathname === cfg.WS_PATH
  ) {
    log.debug("Accepting WebSocket client");
    const wsPair = new WebSocketPair();
    const ws_client = wsPair[0];
    const ws_server = wsPair[1];
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const client = create_ws_client(log, ws_client, ws_server, earlyData);
    try {
    
      
      ctx.waitUntil(handle_client(cfg, log, client));
      return client.resp;
    } catch (err) {
      log.error(`WebSocket accept error: ${err.message}`);
      client.close && client.close();
      return BAD_REQUEST;
    }
  }

  if (cfg.XHTTP_PATH &&
    request.method === 'POST' &&
    url.pathname === cfg.XHTTP_PATH
  ) {
    log.debug("Accepting XHTTP client");
    const client = create_xhttp_client(cfg, request.body);
    ctx.waitUntil(handle_client(cfg, log, client));
    return client.resp;
  }

  if (cfg.DOH_QUERY_PATH && append_slash(url.pathname).endsWith(append_slash(cfg.DOH_QUERY_PATH))) {
    return handle_doh(log, request, url, cfg.UPSTREAM_DOH);
  }

  if (request.method === 'GET' && !request.headers.get('Upgrade')) {
    const o = handle_json(cfg, url, request);
    if (o) {
      return new Response(JSON.stringify(o), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response("Hello World!");
  }

  return BAD_REQUEST;
}

function load_settings(env, settings) {
  const cfg = Object.assign({}, settings, env);
  cfg.TIME_DRIFT = (parseInt(cfg.TIME_ZONE, 10) || 0) * 3600 * 1000;
  ['XHTTP_PATH', 'WS_PATH', 'DOH_QUERY_PATH'].forEach(feature => {
    if (cfg[feature]) cfg[feature] = append_slash(cfg[feature]);
  });
  return cfg;
}

export default {
  fetch: main,
  concat_typed_arrays,
  parse_uuid,
  random_id,
  random_padding,
  validate_uuid,
};
