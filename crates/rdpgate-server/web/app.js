'use strict';

const page = document.body.dataset.page;
const base = location.pathname.replace(/[^/]*$/, '');
const $ = (id) => document.getElementById(id);

// An enrollment token arrives in the URL fragment, which browsers never send
// to servers or put in Referer headers. Read it, then scrub it from the
// address bar and history; sessionStorage (this tab only) survives a reload.
let secret = '';
if (page === 'enroll') {
  secret = location.hash.slice(1) || sessionStorage.getItem('enroll') || '';
  if (secret) sessionStorage.setItem('enroll', secret);
  history.replaceState(null, '', location.pathname);
}

function say(msg, kind) {
  const el = $('status');
  el.textContent = msg;
  el.className = kind || '';
}

function b64uToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufToB64u(buf) {
  let bin = '';
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function api(path, headers, body) {
  const res = await fetch(base + 'api/' + path, {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
    body: JSON.stringify(body === undefined ? {} : body),
    credentials: 'omit',
    cache: 'no-store',
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (!res.ok) throw new Error(data.error || ('Request failed (' + res.status + ')'));
  return data;
}

function creationOptions(o) {
  const pk = o.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  for (const c of pk.excludeCredentials || []) c.id = b64uToBuf(c.id);
  return { publicKey: pk };
}

function requestOptions(o) {
  const pk = o.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  for (const c of pk.allowCredentials || []) c.id = b64uToBuf(c.id);
  return { publicKey: pk };
}

function attestationJSON(c) {
  return {
    id: c.id,
    rawId: bufToB64u(c.rawId),
    type: c.type,
    clientExtensionResults: c.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      attestationObject: bufToB64u(c.response.attestationObject),
      transports: c.response.getTransports ? c.response.getTransports() : undefined,
    },
  };
}

function assertionJSON(c) {
  return {
    id: c.id,
    rawId: bufToB64u(c.rawId),
    type: c.type,
    clientExtensionResults: c.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON),
      authenticatorData: bufToB64u(c.response.authenticatorData),
      signature: bufToB64u(c.response.signature),
      userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : undefined,
    },
  };
}

function explain(err) {
  if (err && err.name === 'NotAllowedError') return 'Cancelled or timed out. Try again.';
  if (err && err.name === 'InvalidStateError') return 'This authenticator is already enrolled.';
  return (err && err.message) || String(err);
}

const clock = (unix) => new Date(unix * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function downloadRdp(host, port) {
  const lines = [
    'full address:s:' + host + ':' + port,
    'prompt for credentials:i:1',
    'authentication level:i:2',
    'enablecredsspsupport:i:1',
    'redirectclipboard:i:1',
    'redirectprinters:i:0',
    'drivestoredirect:s:',
    'screen mode id:i:2',
  ];
  const blob = new Blob([lines.join('\r\n') + '\r\n'], { type: 'application/x-rdp' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = host + '.rdp';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

function login() {
  const go = $('go');
  let revokeToken = '';
  go.addEventListener('click', async () => {
    go.disabled = true;
    try {
      say('Waiting for your passkey…');
      const begin = await api('login/begin');
      const cred = await navigator.credentials.get(requestOptions(begin.options));
      const g = await api('login/finish', { 'X-Login-ID': begin.login_id }, assertionJSON(cred));
      revokeToken = g.revoke_token;
      $('ip').textContent = g.ip;
      $('target').textContent = g.rdp_host + (g.rdp_port === 3389 ? '' : ':' + g.rdp_port);
      $('until').textContent = clock(g.expires);
      $('max').textContent = clock(g.hard_expires);
      $('rdp').onclick = () => downloadRdp(g.rdp_host, g.rdp_port);
      if (g.rdp_sha256) {
        $('sha256').textContent = g.rdp_sha256;
        $('sha1').textContent = g.rdp_sha1;
        $('certnote').hidden = false;
      }
      $('granted').hidden = false;
      go.hidden = true;
      say('Access is open for your IP address.', 'good');
    } catch (e) {
      say(explain(e), 'bad');
      go.disabled = false;
    }
  });
  $('close').addEventListener('click', async () => {
    try {
      await api('revoke', { 'X-Revoke-Token': revokeToken });
      $('granted').hidden = true;
      go.hidden = false;
      go.disabled = false;
      say('Access closed.', 'good');
    } catch (e) {
      say(explain(e), 'bad');
    }
  });
}

function enroll() {
  const hdr = { 'X-Enroll-Token': secret };
  const go = $('go');
  if (!secret) {
    say('This enrollment link is incomplete. On the server run rdpgate-server passkey-enroll again.', 'bad');
    go.disabled = true;
    return;
  }
  go.addEventListener('click', async () => {
    go.disabled = true;
    try {
      say('Waiting for your authenticator…');
      const opts = await api('enroll/begin', hdr, { name: $('name').value.trim() });
      const cred = await navigator.credentials.create(creationOptions(opts));
      await api('enroll/finish', hdr, attestationJSON(cred));
      sessionStorage.removeItem('enroll');
      say('Passkey saved. You can now sign in from the main page.', 'good');
      $('name').disabled = true;
    } catch (e) {
      say(explain(e), 'bad');
      go.disabled = false;
    }
  });
}

if (!window.PublicKeyCredential) {
  say('This browser does not support passkeys.', 'bad');
  $('go').disabled = true;
} else if (page === 'enroll') {
  enroll();
} else {
  login();
}
