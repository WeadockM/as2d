'use strict';

// as2d dashboard. Plain DOM, no framework. Everything that comes from the
// server is inserted as text, never as HTML.

const app = document.getElementById('app');
let session = null;   // from /api/session
let refreshTimer = null;

// ---------- helpers ----------

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

class AuthError extends Error {}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    credentials: 'same-origin',
    headers: { 'X-AS2D-Request': '1', ...(opts.headers || {}) },
  });
  if (res.status === 401 && !path.startsWith('/api/login')) {
    showLogin();
    throw new AuthError('not signed in');
  }
  const isJSON = (res.headers.get('Content-Type') || '').includes('application/json');
  const data = isJSON ? await res.json() : null;
  if (res.status === 403 && data && data.code === 'password_change_required') {
    accountPage(true);
    throw new AuthError('password change required');
  }
  if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
  return { data, status: res.status };
}

const roleRank = { viewer: 1, operator: 2, admin: 3 };
// can reports whether the signed-in role includes min. The server enforces
// this too; the dashboard only uses it to hide what would be refused.
function can(min) {
  return !!session && (roleRank[session.role] || 0) >= roleRank[min];
}

const pad = n => String(n).padStart(2, '0');
function fmtTime(s) {
  if (!s) return '';
  const d = new Date(s);
  if (isNaN(d) || d.getFullYear() < 2000) return '';
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function fmtDate(s) { return fmtTime(s).slice(0, 10); }
function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
function ago(s) {
  const sec = Math.round((Date.now() - new Date(s)) / 1000);
  if (sec < 0) return `in ${until(s)}`;
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}
function until(s) {
  const sec = Math.max(0, Math.round((new Date(s) - Date.now()) / 1000));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${Math.round(sec / 3600)}h`;
}

const stateClass = {
  received: 'ok', delivered: 'ok', failed: 'bad', duplicate: 'warn',
  pending: 'info', awaiting_mdn: 'info', expired: 'bad', expiring: 'warn', ok: 'ok',
};
const stateLabel = { awaiting_mdn: 'awaiting MDN', ok: 'valid' };
function badge(state, label) {
  if (!state) return '';
  return h('span', { class: `badge ${stateClass[state] || ''}` }, label || stateLabel[state] || state);
}

function direction(d) {
  return d === 'inbound'
    ? h('span', { class: 'dir in', title: 'Received from the partner' }, '↓ in')
    : h('span', { class: 'dir out', title: 'Sent to the partner' }, '↑ out');
}

function alertBox(kind, title, text) {
  return h('div', { class: `alert ${kind}`, role: kind === 'bad' ? 'alert' : null }, title ? h('strong', {}, title) : null, text);
}

function render(...nodes) {
  app.replaceChildren(...nodes.flat().filter(n => n != null && n !== false));
}

function loading() { render(h('div', { class: 'loading' }, 'Loading…')); }

function failed(err) {
  if (err instanceof AuthError) return;
  render(alertBox('bad', 'Something went wrong', err.message));
}

// Hash routes look like #/messages?partner=ACME
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query] = raw.split('?');
  return { parts: (path || 'messages').split('/'), params: new URLSearchParams(query || '') };
}
function go(path, params) {
  const q = params && [...params].length ? `?${params}` : '';
  location.hash = `#/${path}${q}`;
}

// autoRefresh re-renders the page periodically, but never while the tab is
// hidden or someone is using a form control on it.
function autoRefresh(fn, ms) {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    const busy = app.contains(document.activeElement) && /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (!document.hidden && !busy) fn();
  }, ms);
}

// ---------- login ----------

function hideChrome() {
  clearInterval(refreshTimer);
  for (const id of ['nav', 'logout', 'whoami']) document.getElementById(id).hidden = true;
}

function showLogin() {
  hideChrome();
  const users = session && session.auth_mode === 'users';
  const username = h('input', { type: 'text', placeholder: 'Username', autocomplete: 'username', required: true, 'aria-label': 'Username' });
  const secret = h('input', {
    type: 'password', required: true,
    placeholder: users ? 'Password' : 'API token', 'aria-label': users ? 'Password' : 'API token',
    autocomplete: 'current-password',
  });
  const msg = h('div');
  const submit = h('button', { class: 'primary', type: 'submit' }, 'Sign in');
  const form = h('form', {
    class: 'card pad login',
    onsubmit: async e => {
      e.preventDefault();
      msg.replaceChildren();
      submit.disabled = true;
      const body = users ? { username: username.value.trim(), password: secret.value } : { token: secret.value };
      try {
        await api('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        await start();
      } catch (err) {
        msg.replaceChildren(alertBox('bad', null, err.message === 'wrong token' ? 'That token is not right.' : err.message));
        secret.value = '';
        secret.focus();
      } finally {
        submit.disabled = false;
      }
    },
  },
    h('h1', {}, 'Sign in'),
    h('p', { class: 'sub' }, users ? `Sign in to ${session.local_id}.` : 'Use the api_token from the daemon\'s configuration.'),
    msg, users ? username : null, secret, submit);
  render(form);
  (users ? username : secret).focus();
}

document.getElementById('logout').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
  session.authenticated = false;
  showLogin();
});

// ---------- account ----------

// accountPage changes the signed-in user's password. forced is set at the
// first sign-in, when a new password must be chosen before anything else.
function accountPage(forced) {
  if (forced) hideChrome(); else clearInterval(refreshTimer);
  const user = session && session.user;
  if (!user) {
    render(h('h1', {}, 'Account'), alertBox('info', null, 'Signed in with the API token. Passwords belong to user accounts.'));
    return;
  }
  const current = h('input', { type: 'password', id: 'current', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', id: 'next', autocomplete: 'new-password', required: true, minlength: '12' });
  const again = h('input', { type: 'password', id: 'again', autocomplete: 'new-password', required: true });
  const msg = h('div');
  const form = h('form', {
    class: 'card pad form',
    onsubmit: async e => {
      e.preventDefault();
      msg.replaceChildren();
      if (next.value !== again.value) {
        msg.replaceChildren(alertBox('bad', null, 'The new passwords do not match.'));
        return;
      }
      try {
        await api('/api/account/password', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ current_password: current.value, new_password: next.value }),
        });
        if (forced) {
          await start();
        } else {
          form.reset();
          msg.replaceChildren(alertBox('info', 'Password changed.', 'Your other sessions have been signed out.'));
        }
      } catch (err) {
        if (!(err instanceof AuthError)) msg.replaceChildren(alertBox('bad', null, err.message));
      }
    },
  },
    forced ? alertBox('info', `Welcome, ${user.username}.`, 'Choose your own password before continuing.') : null,
    msg,
    h('div', { class: 'field' }, h('label', { for: 'current' }, forced ? 'One-time password' : 'Current password'), current),
    h('div', { class: 'field' }, h('label', { for: 'next' }, 'New password'), next,
      h('div', { class: 'hint' }, 'At least 12 characters. A few unrelated words make a strong, memorable password.')),
    h('div', { class: 'field' }, h('label', { for: 'again' }, 'New password again'), again),
    h('button', { class: 'primary', type: 'submit' }, 'Change password'));
  render(
    h('h1', {}, forced ? 'Choose a password' : 'Account'),
    forced ? null : h('p', { class: 'sub' }, `Signed in as ${user.username} (${user.role}).`),
    form);
  current.focus();
}

// ---------- users ----------

const roleHelp = {
  viewer: 'sees messages, the queue, partners and certificates',
  operator: 'also retries failed messages and sends files',
  admin: 'also manages users and reads the audit log',
};

// oneTimePassword shows a new user's or reset password exactly once.
function oneTimePassword(username, password, created) {
  const code = h('code', { class: 'secret' }, password);
  const copy = h('button', {
    class: 'small', type: 'button',
    onclick: async () => {
      try { await navigator.clipboard.writeText(password); copy.textContent = 'Copied'; } catch { copy.textContent = 'Copy failed'; }
    },
  }, 'Copy');
  return h('div', { class: 'alert info' },
    h('strong', {}, created ? `Created ${username}.` : `New one-time password for ${username}.`),
    h('div', { class: 'secret-row' }, code, copy),
    h('div', {}, 'Give it to them privately. It is shown only now; they choose their own password when they first sign in.'));
}

async function usersPage() {
  if (!session.accounts_available) {
    render(h('h1', {}, 'Users'), alertBox('info', 'User accounts are not configured.',
      'Set password_pepper_file and state_dir in the configuration, then create the first admin with as2d -create-admin <username>.'));
    return;
  }
  const { data: users } = await api('/api/users');
  const notice = h('div');
  const me = session.user ? session.user.username.toLowerCase() : '';

  const roleSelect = (u) => {
    const sel = h('select', {
      'aria-label': `Role for ${u.username}`, disabled: u.username.toLowerCase() === me,
      onchange: async () => {
        try {
          await api(`/api/users/${encodeURIComponent(u.username)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role: sel.value }) });
          notice.replaceChildren(alertBox('info', null, `${u.username} is now ${sel.value === 'admin' ? 'an' : 'a'} ${sel.value}.`));
        } catch (err) { sel.value = u.role; notice.replaceChildren(alertBox('bad', null, err.message)); }
      },
    }, ['viewer', 'operator', 'admin'].map(r => h('option', { value: r, selected: u.role === r }, r)));
    return sel;
  };

  const rows = users.map(u => {
    const self = u.username.toLowerCase() === me;
    return h('tr', {},
      h('td', {}, h('strong', {}, u.username), self ? h('span', { class: 'secondary' }, ' (you)') : null),
      h('td', {}, roleSelect(u)),
      h('td', {}, u.disabled ? badge('failed', 'disabled')
        : u.must_change_password ? badge('pending', 'awaiting first sign-in') : badge('ok', 'active')),
      h('td', { class: 'nowrap' }, u.last_login ? fmtTime(u.last_login) : h('span', { class: 'secondary' }, 'never')),
      h('td', { class: 'nowrap' }, self ? null : [
        h('button', {
          class: 'small', onclick: async () => {
            if (!confirm(`Give ${u.username} a new one-time password? They will be signed out everywhere.`)) return;
            try {
              const { data } = await api(`/api/users/${encodeURIComponent(u.username)}/reset-password`, { method: 'POST' });
              notice.replaceChildren(oneTimePassword(u.username, data.temporary_password, false));
            } catch (err) { notice.replaceChildren(alertBox('bad', null, err.message)); }
          },
        }, 'Reset password'), ' ',
        h('button', {
          class: 'small', onclick: async () => {
            try {
              await api(`/api/users/${encodeURIComponent(u.username)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disabled: !u.disabled }) });
              await usersPage();
            } catch (err) { notice.replaceChildren(alertBox('bad', null, err.message)); }
          },
        }, u.disabled ? 'Enable' : 'Disable'),
      ]));
  });

  const newName = h('input', { type: 'text', placeholder: 'Username', required: true, 'aria-label': 'New username', autocomplete: 'off' });
  const newRole = h('select', { 'aria-label': 'Role for the new user' },
    ['viewer', 'operator', 'admin'].map(r => h('option', { value: r, selected: r === 'operator' }, r)));
  const addForm = h('form', {
    class: 'filters',
    onsubmit: async e => {
      e.preventDefault();
      try {
        const { data } = await api('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: newName.value.trim(), role: newRole.value }) });
        await usersPage();
        document.getElementById('user-notice').replaceChildren(oneTimePassword(data.username, data.temporary_password, true));
      } catch (err) { notice.replaceChildren(alertBox('bad', null, err.message)); }
    },
  }, newName, newRole, h('button', { class: 'primary', type: 'submit' }, 'Add user'));

  notice.id = 'user-notice';
  render(
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Users'),
      h('p', { class: 'sub' }, 'Who can sign in to the dashboard, and what they can do.'))),
    notice,
    h('div', { class: 'card pad stack' },
      h('h2', {}, 'Add a user'), addForm,
      h('ul', { class: 'hint role-help' }, Object.entries(roleHelp).map(([r, d]) => h('li', {}, h('strong', {}, r), `: ${d}`)))),
    h('div', { class: 'card result' }, h('div', { class: 'table-wrap' }, h('table', { class: 'middle' },
      h('thead', {}, h('tr', {}, ['User', 'Role', 'Status', 'Last sign-in', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, rows)))));
  clearInterval(refreshTimer);
}

// ---------- audit log ----------

const actionLabel = {
  login: 'signed in', login_failed: 'failed sign-in', login_refused: 'sign-in refused (locked)', logout: 'signed out',
  password_change: 'changed password', password_change_failed: 'failed password change',
  user_create: 'created user', user_role: 'changed role', user_disable: 'disabled user', user_enable: 'enabled user',
  user_password_reset: 'reset password', message_send: 'sent a file', message_retry: 'retried a message',
};

async function auditPage(params) {
  if (!session.accounts_available) {
    render(h('h1', {}, 'Audit log'), alertBox('info', 'User accounts are not configured.', 'The audit log records what signed-in users do.'));
    return;
  }
  const PAGE = 100;
  const page = Math.max(1, parseInt(params.get('page') || '1', 10));
  const filters = { user: params.get('user') || '', action: params.get('action') || '' };
  const q = new URLSearchParams({ limit: PAGE, offset: (page - 1) * PAGE });
  for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
  const { data } = await api(`/api/audit?${q}`);

  const apply = changes => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...filters, ...changes })) if (v) p.set(k, v);
    go('audit', p);
  };
  const userIn = h('input', { type: 'search', placeholder: 'User', value: filters.user, 'aria-label': 'Filter by user' });
  userIn.addEventListener('keydown', e => { if (e.key === 'Enter') apply({ user: userIn.value.trim() }); });
  const actionSel = h('select', { 'aria-label': 'Filter by action', onchange: e => apply({ action: e.target.value }) },
    h('option', { value: '' }, 'All actions'),
    Object.entries(actionLabel).map(([a, l]) => h('option', { value: a, selected: filters.action === a }, l)));

  const describe = e => {
    const d = e.details || {};
    if (e.action === 'user_role') return `${d.from} → ${d.to}`;
    if (e.action === 'user_create') return `as ${d.role}`;
    if (e.action === 'message_send') return d.filename || '';
    return d.reason || '';
  };
  const warn = a => /failed|refused/.test(a);
  const rows = data.entries.map(e => h('tr', {},
    h('td', { class: 'nowrap' }, fmtTime(e.time)),
    h('td', { class: 'nowrap' }, e.user || h('span', { class: 'secondary' }, '(blank)')),
    h('td', {}, warn(e.action) ? badge('failed', actionLabel[e.action] || e.action) : (actionLabel[e.action] || e.action)),
    h('td', {}, e.target || ''),
    h('td', { class: 'secondary' }, describe(e)),
    h('td', { class: 'nowrap secondary mono' }, e.remote || '')));

  const last = Math.min(page * PAGE, data.total);
  render(
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Audit log'),
      h('p', { class: 'sub' }, 'Sign-ins and every change made through the dashboard, newest first.'))),
    h('div', { class: 'filters' }, userIn, actionSel,
      filters.user || filters.action ? h('button', { class: 'link', onclick: () => go('audit') }, 'Clear filters') : null),
    h('div', { class: 'card' },
      data.entries.length
        ? h('div', { class: 'table-wrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Time', 'User', 'Action', 'Target', 'Details', 'From'].map(t => h('th', {}, t)))),
            h('tbody', {}, rows)))
        : h('div', { class: 'empty' }, 'Nothing recorded yet.'),
      h('div', { class: 'pager' },
        h('span', {}, data.total ? `${(page - 1) * PAGE + 1}–${last} of ${data.total}` : 'No entries'),
        h('div', {},
          h('button', { class: 'small', disabled: page <= 1, onclick: () => apply({ page: String(page - 1) }) }, 'Previous'),
          h('button', { class: 'small', disabled: last >= data.total, onclick: () => apply({ page: String(page + 1) }) }, 'Next')))));
  clearInterval(refreshTimer);
}

// ---------- messages ----------

const PAGE = 50;

async function messagesPage(params) {
  const filters = {
    q: params.get('q') || '', direction: params.get('direction') || '', partner: params.get('partner') || '',
    state: params.get('state') || '', since: params.get('since') || '', until: params.get('until') || '',
  };
  const page = Math.max(1, parseInt(params.get('page') || '1', 10));

  const query = new URLSearchParams({ limit: PAGE, offset: (page - 1) * PAGE });
  for (const k of ['q', 'direction', 'partner', 'state']) if (filters[k]) query.set(k, filters[k]);
  // Dates are local days; until is inclusive.
  if (filters.since) query.set('since', localDay(filters.since).toISOString());
  if (filters.until) { const d = localDay(filters.until); d.setDate(d.getDate() + 1); query.set('until', d.toISOString()); }

  const { data } = await api(`/api/archive/messages?${query}`);

  const apply = changes => {
    const p = new URLSearchParams();
    const next = { ...filters, ...changes };
    for (const [k, v] of Object.entries(next)) if (v) p.set(k, v);
    go('messages', p);
  };
  const select = (key, label, options) => h('select', { 'aria-label': label, onchange: e => apply({ [key]: e.target.value }) },
    h('option', { value: '' }, label),
    options.map(([v, l]) => h('option', { value: v, selected: filters[key] === v }, l)));

  const search = h('input', { type: 'search', placeholder: 'Search file name, Message-ID, subject, correlation ID', value: filters.q, 'aria-label': 'Search' });
  search.addEventListener('keydown', e => { if (e.key === 'Enter') apply({ q: search.value.trim() }); });
  search.addEventListener('search', () => apply({ q: search.value.trim() }));

  const partnerOptions = (data.partners || []).map(p => [p, p]);
  if (filters.partner && !data.partners?.includes(filters.partner)) partnerOptions.push([filters.partner, filters.partner]);

  const rows = data.messages.map(m => h('tr', { class: 'clickable', onclick: () => go(`messages/${m.id}`) },
    h('td', { class: 'nowrap' }, fmtTime(m.time), h('div', { class: 'secondary' }, ago(m.time))),
    h('td', {}, direction(m.direction)),
    h('td', { class: 'nowrap' }, m.partner),
    h('td', {}, h('div', { class: 'truncate' }, m.filename || h('span', { class: 'secondary' }, '—')),
      h('div', { class: 'secondary truncate mono' }, m.message_id)),
    h('td', { class: 'num nowrap' }, fmtSize(m.size)),
    h('td', {}, badge(m.state), m.error ? h('div', { class: 'secondary truncate', title: m.error }, m.error) : null),
    h('td', {}, m.forward_state ? badge(m.forward_state) : h('span', { class: 'secondary' }, '—')),
  ));

  const first = data.total ? (page - 1) * PAGE + 1 : 0;
  const last = Math.min(page * PAGE, data.total);
  const pager = h('div', { class: 'pager' },
    h('span', {}, data.total ? `${first}–${last} of ${data.total}` : 'No messages'),
    h('div', {},
      h('button', { class: 'small', disabled: page <= 1, onclick: () => apply({ page: String(page - 1) }) }, 'Previous'),
      h('button', { class: 'small', disabled: last >= data.total, onclick: () => apply({ page: String(page + 1) }) }, 'Next')));

  const anyFilter = Object.values(filters).some(Boolean);
  render(
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Messages'), h('p', { class: 'sub' }, 'Everything received from and sent to partners, newest first.'))),
    h('div', { class: 'filters' },
      search,
      select('direction', 'All directions', [['inbound', 'Received'], ['outbound', 'Sent']]),
      select('partner', 'All partners', partnerOptions),
      select('state', 'All states', [['received', 'Received'], ['delivered', 'Delivered'], ['failed', 'Failed'], ['duplicate', 'Duplicate']]),
      h('label', { class: 'inline' }, 'From', h('input', { type: 'date', value: filters.since, onchange: e => apply({ since: e.target.value }) })),
      h('label', { class: 'inline' }, 'To', h('input', { type: 'date', value: filters.until, onchange: e => apply({ until: e.target.value }) })),
      anyFilter ? h('button', { class: 'link', onclick: () => go('messages') }, 'Clear filters') : null),
    h('div', { class: 'card' },
      data.messages.length
        ? h('div', { class: 'table-wrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Time', 'Direction', 'Partner', 'File', 'Size', 'Status', 'Forward'].map(t => h('th', {}, t)))),
            h('tbody', {}, rows)))
        : h('div', { class: 'empty' }, anyFilter ? 'No messages match these filters.' : 'No messages yet.'),
      pager));
  autoRefresh(() => messagesPage(params).catch(() => {}), 15000);
}

function localDay(s) {
  const [y, m, d] = s.split('-').map(Number);
  return new Date(y, m - 1, d);
}

// ---------- message detail ----------

async function messagePage(id) {
  const { data } = await api(`/api/archive/messages/${encodeURIComponent(id)}`);
  const m = data.message;
  const job = data.job;

  const prop = (label, value) => value === '' || value == null || value === false ? null : [h('dt', {}, label), h('dd', {}, value)];
  const security = m.direction === 'inbound'
    ? h('div', { class: 'chips' },
        badge(m.encrypted ? 'ok' : '', 'encrypted') || h('span', { class: 'badge' }, 'not encrypted'),
        badge(m.signed ? 'ok' : '', 'signed') || h('span', { class: 'badge' }, 'not signed'),
        m.compressed ? h('span', { class: 'badge info' }, 'compressed') : null)
    : null;

  const retry = job && job.state === 'failed' && can('operator') ? h('button', {
    class: 'primary',
    onclick: async e => {
      e.target.disabled = true;
      try {
        await api(`/api/messages/${encodeURIComponent(job.id)}/retry`, { method: 'POST' });
        go('queue');
      } catch (err) { e.target.disabled = false; alert(err.message); }
    },
  }, job.kind === 'forward' ? 'Retry forward' : 'Retry send') : null;

  const files = h('ul', { class: 'files' }, data.files.map(f => h('li', {},
    h('a', { href: `/api/archive/messages/${m.id}/files/${f.path.split('/').map(encodeURIComponent).join('/')}`, download: '' }, f.path),
    h('span', { class: 'secondary' }, fmtSize(f.size)))));

  render(
    h('p', {}, h('a', { href: '#/messages', onclick: e => { if (history.length > 1) { e.preventDefault(); history.back(); } } }, '← Messages')),
    h('div', { class: 'page-head' },
      h('div', {},
        h('h1', {}, m.filename || m.message_id),
        h('p', { class: 'sub' }, direction(m.direction), ` ${m.direction === 'inbound' ? 'from' : 'to'} ${m.partner} · ${fmtTime(m.time)}`)),
      h('div', { class: 'chips' }, badge(m.state), retry)),
    m.error ? alertBox('bad', 'Error', m.error) : null,
    h('div', { class: 'detail-grid' },
      h('div', { class: 'stack' },
        h('div', { class: 'card pad' }, h('h2', {}, 'Message'),
          h('dl', { class: 'props' },
            prop('Message-ID', h('span', { class: 'mono' }, m.message_id)),
            prop('Partner', m.partner),
            prop('File name', m.filename),
            prop('Content type', m.content_type),
            prop('Size', m.size ? fmtSize(m.size) : ''),
            prop('Subject', m.subject),
            prop('Correlation ID', m.correlation_id),
            prop('Security', security))),
        h('div', { class: 'card pad' }, h('h2', {}, 'Receipt (MDN)'),
          m.disposition || m.mic
            ? h('dl', { class: 'props' },
                prop('Disposition', m.disposition),
                prop('MIC', h('span', { class: 'mono' }, m.mic)))
            : h('p', { class: 'secondary' }, m.direction === 'inbound' ? 'The partner did not ask for an MDN.' : 'No MDN recorded.')),
        h('div', { class: 'card pad' },
          h('details', {}, h('summary', {}, 'Raw meta.json'), h('pre', { class: 'json' }, JSON.stringify(data.meta, null, 2))))),
      h('div', { class: 'stack' },
        m.forward_state || job ? h('div', { class: 'card pad' }, h('h2', {}, job && job.kind === 'send' ? 'Delivery' : 'Forward'),
          h('dl', { class: 'props' },
            prop('State', badge(job ? job.state : m.forward_state)),
            prop('Attempts', job ? String(job.attempts) : ''),
            prop('HTTP status', job && job.http_status ? String(job.http_status) : ''),
            prop('Next attempt', job && job.next_attempt ? `${fmtTime(job.next_attempt)} (in ${until(job.next_attempt)})` : ''),
            prop('Last error', job && job.last_error !== m.error ? job.last_error : ''),
            prop('Job', job ? h('span', { class: 'mono' }, job.id) : ''))) : null,
        h('div', { class: 'card pad' }, h('h2', {}, 'Files'), files))));
  clearInterval(refreshTimer);
}

// ---------- queue ----------

async function queuePage(params) {
  const view = params.get('view') || 'active';
  const { data } = await api('/api/messages?limit=500');
  const jobs = data.filter(j =>
    view === 'all' || (view === 'failed' ? j.state === 'failed' : j.state === 'pending' || j.state === 'awaiting_mdn'));

  const tab = (v, label, n) => h('button', { class: `small ${view === v ? 'primary' : ''}`, onclick: () => go('queue', new URLSearchParams({ view: v })) }, `${label} (${n})`);
  const counts = {
    active: data.filter(j => j.state === 'pending' || j.state === 'awaiting_mdn').length,
    failed: data.filter(j => j.state === 'failed').length,
  };

  const rows = jobs.map(j => h('tr', {},
    h('td', { class: 'nowrap' }, fmtTime(j.created), h('div', { class: 'secondary' }, ago(j.created))),
    h('td', {}, j.kind === 'forward' ? h('span', { class: 'badge' }, 'forward') : h('span', { class: 'badge info' }, 'send')),
    h('td', { class: 'nowrap' }, j.partner),
    h('td', {}, h('div', { class: 'truncate' }, j.filename), j.correlation_id ? h('div', { class: 'secondary' }, j.correlation_id) : null),
    h('td', {}, badge(j.state)),
    h('td', { class: 'num' }, String(j.attempts)),
    h('td', {},
      j.state === 'pending' && j.next_attempt ? h('div', {}, `next try in ${until(j.next_attempt)}`) : null,
      j.last_error ? h('div', { class: 'secondary truncate', title: j.last_error }, j.last_error) : null),
    h('td', {}, j.state === 'failed' && can('operator') ? h('button', {
      class: 'small',
      onclick: async e => {
        e.target.disabled = true;
        try { await api(`/api/messages/${encodeURIComponent(j.id)}/retry`, { method: 'POST' }); queuePage(params); }
        catch (err) { e.target.disabled = false; alert(err.message); }
      },
    }, 'Retry') : null)));

  render(
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Queue'), h('p', { class: 'sub' }, 'Sends to partners and forwards to downstream systems, with their retries.')),
      h('div', { class: 'chips' }, tab('active', 'In progress', counts.active), tab('failed', 'Failed', counts.failed), tab('all', 'All', data.length))),
    h('div', { class: 'card' },
      jobs.length
        ? h('div', { class: 'table-wrap' }, h('table', {},
            h('thead', {}, h('tr', {}, ['Created', 'Kind', 'Partner', 'File', 'State', 'Tries', 'Details', ''].map(t => h('th', {}, t)))),
            h('tbody', {}, rows)))
        : h('div', { class: 'empty' }, view === 'failed' ? 'No failed jobs.' : view === 'active' ? 'Nothing in progress.' : 'The queue is empty.')));
  autoRefresh(() => queuePage(params).catch(() => {}), 5000);
}

// ---------- partners ----------

let partnerCache = null;

async function loadPartners() {
  const { data } = await api('/api/partners');
  partnerCache = data;
  const certs = [data.local.cert, ...data.partners.map(p => p.cert)].filter(Boolean);
  const dot = document.getElementById('cert-dot');
  const expired = certs.some(c => c.status === 'expired');
  const expiring = certs.some(c => c.status === 'expiring');
  dot.hidden = !expired && !expiring;
  dot.className = `dot ${expired ? '' : 'warn'}`;
  dot.title = expired ? 'A certificate has expired' : 'A certificate expires soon';
  return data;
}

function certBlock(c, downloadHref) {
  if (!c) return h('p', { class: 'secondary' }, 'No certificate.');
  const status = c.status === 'expired' ? 'expired'
    : c.status === 'expiring' ? `expires in ${c.days_left} days` : `valid, ${c.days_left} days left`;
  return h('dl', { class: 'props' },
    h('dt', {}, 'Certificate'), h('dd', {}, badge(c.status, status)),
    h('dt', {}, 'Valid'), h('dd', {}, `${fmtDate(c.not_before)} to ${fmtDate(c.not_after)}`),
    h('dt', {}, 'Subject'), h('dd', {}, c.subject, c.self_signed ? h('span', { class: 'secondary' }, ' (self-signed)') : null),
    h('dt', {}, 'SHA-256'), h('dd', { class: 'mono' }, c.sha256.match(/.{1,2}/g).join(':')),
    h('dt', {}, ''), h('dd', {}, h('a', { class: 'button small', href: downloadHref, download: '' }, 'Download certificate')));
}

async function partnersPage() {
  const data = await loadPartners();
  const local = data.local;

  const cards = data.partners.map(p => {
    const o = p.outbound;
    const f = p.forward;
    return h('div', { class: 'card pad' },
      h('div', { class: 'partner-head' },
        h('h2', {}, p.id),
        h('a', { href: `#/messages?partner=${encodeURIComponent(p.id)}` }, 'Messages →')),
      h('dl', { class: 'props' },
        h('dt', {}, 'Receiving'), h('dd', {}, h('div', { class: 'chips' },
          p.require_encryption ? h('span', { class: 'badge' }, 'requires encryption') : null,
          p.require_signature ? h('span', { class: 'badge' }, 'requires signature') : null,
          !p.require_encryption && !p.require_signature ? h('span', { class: 'secondary' }, 'no requirements') : null)),
        h('dt', {}, 'Sending'), h('dd', {}, o
          ? [h('div', { class: 'mono' }, o.url),
             h('div', { class: 'secondary' }, [
               o.sign ? `signed (${o.micalg})` : 'unsigned',
               o.encrypt ? `encrypted (${o.cipher})` : 'not encrypted',
               o.compress !== 'none' ? `compressed ${o.compress}` : null,
               o.mdn === 'none' ? 'no MDN' : `${o.signed_mdn ? 'signed ' : ''}${o.mdn} MDN`,
             ].filter(Boolean).join(' · '))]
          : h('span', { class: 'secondary' }, 'not configured')),
        h('dt', {}, 'Forward'), h('dd', {}, f
          ? [h('div', { class: 'mono' }, f.url), h('div', { class: 'secondary' }, `${f.mode}${f.username ? ` · as ${f.username}` : ''}`)]
          : h('span', { class: 'secondary' }, 'not configured'))),
      h('div', { class: 'result' }, certBlock(p.cert, `/api/certs/partners/${encodeURIComponent(p.id)}.pem`)));
  });

  const warnings = [local.cert, ...data.partners.map(p => p.cert)].filter(c => c && c.status !== 'ok');
  render(
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Partners'), h('p', { class: 'sub' }, 'Your station and the partners it trades with. Edit them in the configuration file.'))),
    warnings.length ? alertBox(warnings.some(c => c.status === 'expired') ? 'bad' : 'warn', 'Certificates need attention',
      'At least one certificate below has expired or expires within 30 days. Partners must receive a new certificate before the old one expires.') : null,
    h('div', { class: 'card pad stack' },
      h('div', { class: 'partner-head' }, h('div', {}, h('h2', {}, `Your station: ${local.id}`),
        h('p', { class: 'hint' }, 'Partners encrypt to this certificate and use it to check your signatures. Send it to them; never send the key.'))),
      certBlock(local.cert, '/api/certs/local.pem')),
    h('h2', { class: 'result' }, `Trading partners (${data.partners.length})`),
    data.partners.length ? h('div', { class: 'partners' }, cards) : h('div', { class: 'card empty' }, 'No partners configured.'));
  clearInterval(refreshTimer);
}

// ---------- send ----------

async function sendPage() {
  const data = partnerCache || await loadPartners();
  const partners = data.partners.filter(p => p.outbound);
  if (!partners.length) {
    render(h('h1', {}, 'Send a file'), alertBox('info', 'No partners to send to', 'Add an "outbound" section to a partner in the configuration to send to it.'));
    return;
  }

  const partnerSel = h('select', { id: 'partner', required: true }, partners.map(p => h('option', { value: p.id }, p.id)));
  const urlNote = h('div', { class: 'hint mono' });
  const showURL = () => { urlNote.textContent = `→ ${partners.find(p => p.id === partnerSel.value).outbound.url}`; };
  partnerSel.addEventListener('change', showURL);
  showURL();
  const fileIn = h('input', { type: 'file', id: 'file', required: true });
  const subject = h('input', { type: 'text', id: 'subject', placeholder: 'Optional' });
  const corr = h('input', { type: 'text', id: 'corr', placeholder: 'Optional, e.g. a document number' });
  const wait = h('input', { type: 'checkbox', id: 'wait', checked: true });
  const submit = h('button', { class: 'primary', type: 'submit' }, 'Send');
  const result = h('div', { class: 'result' });

  const form = h('form', {
    class: 'card pad form',
    onsubmit: async e => {
      e.preventDefault();
      const file = fileIn.files[0];
      if (!file) return;
      submit.disabled = true;
      submit.textContent = wait.checked ? 'Sending and waiting for the MDN…' : 'Sending…';
      result.replaceChildren();
      const q = new URLSearchParams({ partner: partnerSel.value, filename: file.name });
      if (subject.value.trim()) q.set('subject', subject.value.trim());
      if (wait.checked) q.set('wait', '120s');
      const headers = {};
      if (file.type) headers['Content-Type'] = file.type;
      if (corr.value.trim()) headers['X-Correlation-ID'] = corr.value.trim();
      try {
        const { data: job } = await api(`/api/messages?${q}`, { method: 'POST', headers, body: file });
        result.replaceChildren(sendResult(job));
      } catch (err) {
        if (!(err instanceof AuthError)) result.replaceChildren(alertBox('bad', 'Not sent', err.message));
      } finally {
        submit.disabled = false;
        submit.textContent = 'Send';
      }
    },
  },
    alertBox('warn', 'This sends a real AS2 message.', 'The file goes to the partner\'s live endpoint, signed and encrypted as configured for that partner.'),
    h('div', { class: 'field' }, h('label', { for: 'partner' }, 'Partner'), partnerSel, urlNote),
    h('div', { class: 'field' }, h('label', { for: 'file' }, 'File'), fileIn),
    h('div', { class: 'field' }, h('label', { for: 'subject' }, 'Subject'), subject),
    h('div', { class: 'field' }, h('label', { for: 'corr' }, 'Correlation ID'), corr),
    h('div', { class: 'field' }, h('label', { class: 'check' }, wait, 'Wait for the partner\'s MDN (up to 2 minutes)')),
    submit, result);

  render(h('h1', {}, 'Send a file'), h('p', { class: 'sub' }, 'Queue a file for a partner. It is retried automatically if the partner is unreachable.'), form);
  clearInterval(refreshTimer);
}

function sendResult(job) {
  const final = job.state === 'delivered' || job.state === 'failed';
  const kind = job.state === 'delivered' ? 'info' : job.state === 'failed' ? 'bad' : 'info';
  const title = job.state === 'delivered' ? 'Delivered: the partner confirmed receipt.'
    : job.state === 'failed' ? 'Failed.'
    : 'Queued. The result will appear in the queue.';
  return h('div', {},
    alertBox(kind, title, final ? null : `Current state: ${stateLabel[job.state] || job.state}.`),
    h('dl', { class: 'props' },
      h('dt', {}, 'State'), h('dd', {}, badge(job.state)),
      job.disposition ? [h('dt', {}, 'Disposition'), h('dd', {}, job.disposition)] : null,
      job.mic ? [h('dt', {}, 'MIC'), h('dd', { class: 'mono' }, job.mic)] : null,
      job.last_error ? [h('dt', {}, 'Error'), h('dd', {}, job.last_error)] : null,
      h('dt', {}, 'Message-ID'), h('dd', { class: 'mono' }, job.message_id || '(assigned when sent)'),
      h('dt', {}, 'Job'), h('dd', {}, h('a', { href: '#/queue?view=all' }, job.id))));
}

// ---------- router ----------

async function route() {
  if (!session) return;
  const { parts, params } = parseHash();
  const name = parts[0];
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.route === name);
  loading();
  try {
    if (name === 'messages' && parts[1]) await messagePage(parts[1]);
    else if (name === 'queue' && session.sending_enabled) await queuePage(params);
    else if (name === 'partners') await partnersPage();
    else if (name === 'send' && session.sending_enabled && can('operator')) await sendPage();
    else if (name === 'account') accountPage(false);
    else if (name === 'users' && can('admin')) await usersPage();
    else if (name === 'audit' && can('admin')) await auditPage(params);
    else await messagesPage(params);
  } catch (err) {
    failed(err);
  }
}

async function start() {
  const { data } = await api('/api/session');
  session = data;
  document.getElementById('station').textContent = data.local_id;
  document.title = `as2d · ${data.local_id}`;
  if (data.auth_required && !data.authenticated) {
    showLogin();
    return;
  }
  if (data.user && data.user.must_change_password) {
    accountPage(true);
    return;
  }
  document.getElementById('nav').hidden = false;
  document.getElementById('logout').hidden = !data.auth_required;
  const whoami = document.getElementById('whoami');
  whoami.hidden = !data.user;
  if (data.user) {
    whoami.textContent = data.user.username;
    whoami.title = `Signed in as ${data.user.username} (${data.user.role}). Change your password here.`;
  }
  for (const a of document.querySelectorAll('#nav a')) {
    a.hidden = (a.hasAttribute('data-needs-queue') && !data.sending_enabled)
      || (a.hasAttribute('data-needs-accounts') && !data.accounts_available)
      || (a.dataset.needsRole && !can(a.dataset.needsRole));
  }
  loadPartners().catch(() => {}); // for the certificate warning dot
  await route();
}

window.addEventListener('hashchange', route);
start().catch(failed);
