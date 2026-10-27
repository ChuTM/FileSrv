/* ============================================================
 * Admin console front-end logic (hand-written, zero dependencies,
 * zero external requests)
 *
 * Security model:
 *  - The admin token lives only in sessionStorage, never in
 *    localStorage / URL / cookie.
 *  - All API-returned data is rendered via textContent / DOM
 *    attributes; innerHTML is never used on untrusted data
 *    (see the INTEGRATION.md checklist).
 *  - app_secret is shown exactly once after create/rotate and is
 *    never loaded into the page again.
 * ============================================================
 */
(function () {
  'use strict';

  var TOKEN_KEY = 'fs_admin_token';

  /* API base: resolved relative to this page's location. When the page
   * is served at /admin/ or /admin/index.html this resolves to /admin/v1/,
   * same origin as the admin_router's /admin/v1/* — no hard-coded host/port. */
  var API_BASE = new URL('v1/', document.baseURI).pathname.replace(/\/$/, '');

  /* ---------- Small DOM helpers (no innerHTML for data) ---------- */

  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'html') el.innerHTML = v; /* static skeleton only; never carries user data */
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') {
          el.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (k === 'dataset') {
          Object.keys(v).forEach(function (dk) { el.dataset[dk] = v[dk]; });
        } else {
          el.setAttribute(k, v);
        }
      });
    }
    if (children) {
      (Array.isArray(children) ? children : [children]).forEach(function (c) {
        if (c == null || c === false) return;
        el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return el;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  /* ---------- Formatting ---------- */

  function fmtBytes(n) {
    if (n == null || isNaN(n)) return '—';
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB'];
    var v = n, u = -1;
    do { v /= 1024; u++; } while (v >= 1024 && u < units.length - 1);
    return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[u];
  }

  function fmtTs(unixSec) {
    if (!unixSec) return '—';
    var d = new Date(unixSec * 1000);
    var p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  /* ---------- API calls ---------- */

  function token() { return sessionStorage.getItem(TOKEN_KEY); }

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { 'Authorization': 'Bearer ' + token() }
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(API_BASE + path, opts).then(function (res) {
      if (res.status === 401) { doLogout(); throw new ApiError(401, 'unauthorized', 'Token invalid or expired. Please sign in again.'); }
      return res.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = null; }
        if (!res.ok) {
          var err = (data && data.error) || {};
          throw new ApiError(res.status, err.code || 'error', err.message || ('HTTP ' + res.status));
        }
        return { status: res.status, data: data };
      });
    });
  }

  function ApiError(status, code, message) { this.status = status; this.code = code; this.message = message; }
  ApiError.prototype = Object.create(Error.prototype);

  /* ---------- Shared UI components ---------- */

  function showGlobalError(msg) {
    var el = document.getElementById('global-error');
    if (!msg) { el.hidden = true; el.textContent = ''; return; }
    el.textContent = msg;
    el.hidden = false;
  }

  function openModal(opts) {
    var root = document.getElementById('modal-root');
    clear(root);
    var card = h('div', { class: 'modal' + (opts.wide ? ' wide' : '') },
      [h('h3', { text: opts.title })]
        .concat(opts.body ? [opts.body] : [])
        .concat([opts.actions ? h('div', { class: 'modal-actions' }, opts.actions) : null]));
    var overlay = h('div', { class: 'modal-overlay' }, [card]);
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) closeModal(); });
    root.appendChild(overlay);
    return { overlay: overlay, card: card };
  }

  function closeModal() { clear(document.getElementById('modal-root')); }

  function confirmModal(title, message, confirmLabel, danger, onConfirm) {
    var busy = false;
    var btn = h('button', {
      class: 'btn ' + (danger ? 'btn-danger' : 'btn-primary'),
      text: confirmLabel,
      onclick: function () {
        if (busy) return; busy = true;
        Promise.resolve(onConfirm()).then(closeModal).catch(function (e) {
          busy = false;
          showGlobalError(e.message);
        });
      }
    });
    openModal({
      title: title,
      body: h('p', { text: message }),
      actions: [
        h('button', { class: 'btn btn-ghost', text: 'Cancel', onclick: closeModal }),
        btn
      ]
    });
  }

  function badge(status, label) {
    return h('span', { class: 'badge badge-' + status, text: label });
  }

  /* ---------- Login / logout ---------- */

  function doLogout() {
    sessionStorage.removeItem(TOKEN_KEY);
    document.getElementById('app-shell').hidden = true;
    document.getElementById('view-login').hidden = false;
    document.getElementById('login-error').hidden = true;
  }

  function afterLogin() {
    document.getElementById('view-login').hidden = true;
    document.getElementById('app-shell').hidden = false;
    switchView('apps');
    loadApps();
  }

  function initLogin() {
    var form = document.getElementById('login-form');
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = document.getElementById('login-token');
      var errEl = document.getElementById('login-error');
      var t = input.value.trim();
      if (!t) return;
      sessionStorage.setItem(TOKEN_KEY, t);
      api('GET', '/apps').then(function () {
        afterLogin();
      }).catch(function (err) {
        sessionStorage.removeItem(TOKEN_KEY);
        errEl.textContent = (err.status === 401) ? 'Invalid token. Sign-in failed.' : ('Cannot reach the admin API: ' + err.message);
        errEl.hidden = false;
      });
    });
    document.getElementById('btn-logout').addEventListener('click', doLogout);
  }

  /* ---------- View switching ---------- */

  var VIEW_TITLES = { apps: 'Apps', audit: 'Audit Log', backup: 'Backup' };
  var currentView = 'apps';

  function switchView(name) {
    currentView = name;
    document.getElementById('view-title').textContent = VIEW_TITLES[name];
    ['apps', 'audit', 'backup'].forEach(function (v) {
      document.getElementById('view-' + v).hidden = (v !== name);
    });
    document.querySelectorAll('#side-nav .nav-item').forEach(function (b) {
      b.classList.toggle('active', b.dataset.view === name);
    });
    renderTopActions();
    showGlobalError('');
  }

  function renderTopActions() {
    var wrap = document.getElementById('topbar-actions');
    clear(wrap);
    if (currentView === 'apps') {
      wrap.appendChild(h('button', {
        class: 'btn btn-primary', text: 'Create App', onclick: openCreateAppModal
      }));
    } else if (currentView === 'audit') {
      wrap.appendChild(h('button', {
        class: 'btn btn-ghost', text: 'Refresh', onclick: loadAudit
      }));
    }
  }

  /* ---------- App list ---------- */

  function loadApps() {
    var wrap = document.getElementById('apps-table-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/apps').then(function (res) {
      renderApps(res.data.apps || []);
    }).catch(function (e) {
      showGlobalError(e.message);
    });
  }

  function renderApps(apps) {
    var wrap = document.getElementById('apps-table-wrap');
    clear(wrap);
    if (!apps.length) {
      wrap.appendChild(h('div', { class: 'empty', text: 'No apps yet. Use "Create App" in the top-right corner.' }));
      return;
    }

    var table = h('table', {}, [
      h('thead', {}, [h('tr', {}, [
        th('App'), th('App Key'), th('Status'),
        th('Usage'), th('Quota'), th('Max File'), th('Created'), th('Actions', 'right')
      ])]),
      h('tbody', {}, apps.map(function (a) { return appRow(a); }))
    ]);
    wrap.appendChild(table);
  }

  function th(text, align) {
    return h('th', align === 'right' ? { class: 'num', text: text } : { text: text });
  }

  function appRow(a) {
    var deleted = !!a.deleted_at;
    var statusBadge = deleted ? badge('danger', 'Deleted')
      : a.enabled ? badge('ok', 'Active') : badge('warn', 'Disabled');

    var pct = (a.quota_bytes > 0 && a.usage_bytes != null)
      ? Math.min(100, Math.round(a.usage_bytes / a.quota_bytes * 100)) : null;
    var fillCls = pct == null ? '' : (pct >= 100 ? ' full' : pct >= 80 ? ' hot' : '');

    var usageCell = h('div', { class: 'quota' }, [
      h('span', { text: fmtBytes(a.usage_bytes) }),
      h('div', { class: 'quota-bar' }, [
        h('div', { class: 'quota-fill' + fillCls, style: 'width:' + (pct || 0) + '%' })
      ])
    ]);

    var actions = h('div', { style: 'display:flex;gap:6px;flex-wrap:wrap;' }, [
      h('button', { class: 'btn btn-ghost btn-sm', text: 'Usage', onclick: function () { openUsage(a.app_id); } }),
      h('button', { class: 'btn btn-ghost btn-sm', text: 'Users', onclick: function () { openUsers(a); } }),
      deleted ? null : h('button', {
        class: 'btn btn-ghost btn-sm',
        text: a.enabled ? 'Disable' : 'Enable',
        onclick: function () { toggleApp(a); }
      }),
      deleted ? null : h('button', {
        class: 'btn btn-ghost btn-sm', text: 'Rotate Secret',
        onclick: function () { openRotate(a); }
      }),
      deleted ? null : h('button', {
        class: 'btn btn-danger-ghost btn-sm', text: 'Delete',
        onclick: function () { deleteApp(a); }
      })
    ]);

    return h('tr', {}, [
      h('td', {}, [
        h('div', { text: a.name || '(unnamed)' }),
        h('div', { class: 'cell-muted', text: 'ID #' + a.app_id })
      ]),
      h('td', {}, [h('span', { class: 'mono cell-2', text: a.app_key || '—' })]),
      h('td', {}, [statusBadge]),
      h('td', {}, [usageCell]),
      h('td', { class: 'cell-2', text: fmtBytes(a.quota_bytes) }),
      h('td', { class: 'cell-2', text: fmtBytes(a.max_payload_bytes) }),
      h('td', { class: 'cell-2', text: fmtTs(a.created_at) }),
      h('td', { class: 'num' }, [actions])
    ]);
  }

  /* ---------- Create app ---------- */

  function openCreateAppModal() {
    var nameI = h('input', { type: 'text', required: true, maxlength: '120', placeholder: 'e.g. Support Desk' });
    var quotaGiB = h('input', { type: 'number', min: '1', step: '1', value: '10' });
    var maxMiB = h('input', { type: 'number', min: '1', step: '1', value: '100' });

    var body = h('div', {}, [
      field('App Name', nameI),
      field('Storage Quota (GiB, 1 GiB = 1024³ B)', quotaGiB),
      field('Max File Size (MiB)', maxMiB)
    ]);

    var submit = h('button', {
      class: 'btn btn-primary', text: 'Create',
      onclick: function () {
        var name = nameI.value.trim();
        if (!name) { nameI.focus(); return; }
        var quota = parseInt(quotaGiB.value, 10) * 1024 * 1024 * 1024;
        var maxp = parseInt(maxMiB.value, 10) * 1024 * 1024;
        if (!quota || quota <= 0 || !maxp || maxp <= 0) { showGlobalError('Quota and max file size must be positive integers.'); return; }
        api('POST', '/apps', { name: name, quota_bytes: quota, max_payload_bytes: maxp }).then(function (res) {
          closeModal();
          showSecretOnce('App created', res.data);
          loadApps();
        }).catch(function (e) { showGlobalError(e.message); });
      }
    });

    openModal({ title: 'Create App', body: body, actions: [
      h('button', { class: 'btn btn-ghost', text: 'Cancel', onclick: closeModal }), submit
    ]});
  }

  function field(label, inputEl) {
    return h('label', { class: 'field' }, [
      h('span', { class: 'field-label', text: label }), inputEl
    ]);
  }

  /* ---------- Usage details ---------- */

  function openUsage(id) {
    api('GET', '/apps/' + id + '/usage').then(function (res) {
      var u = res.data;
      var rows = [
        ['Used', fmtBytes(u.usage_bytes)],
        ['Quota', fmtBytes(u.quota_bytes)],
        ['Files', String(u.file_count)],
        ['Active download tokens', String(u.active_token_count)]
      ];
      var body = h('table', {}, [h('tbody', {}, rows.map(function (r) {
        return h('tr', {}, [
          h('td', { class: 'cell-2', text: r[0] }),
          h('td', { class: 'mono', text: r[1] })
        ]);
      }))]);
      openModal({ title: 'Usage · App #' + id, body: body, actions: [
        h('button', { class: 'btn btn-ghost', text: 'Close', onclick: closeModal })
      ]});
    }).catch(function (e) { showGlobalError(e.message); });
  }

  /* ---------- Enable / disable ---------- */

  function toggleApp(a) {
    var next = !a.enabled;
    confirmModal(
      next ? 'Enable App' : 'Disable App',
      next ? 'Re-enable "' + (a.name || '') + '"?'
           : 'Once disabled, all uploads/downloads/token signing for this app are rejected immediately. Disable it?',
      next ? 'Enable' : 'Disable', !next,
      function () {
        return api('PATCH', '/apps/' + a.app_id, { enabled: next }).then(loadApps);
      }
    );
  }

  /* ---------- Rotate secret ---------- */

  function openRotate(a) {
    confirmModal(
      'Rotate App Secret',
      'After rotation, the old secret for "' + (a.name || '') + '" is invalid immediately; all HMAC signatures and user JWTs issued with it will fail. Make sure your backend is updated before continuing.',
      'Rotate', true,
      function () {
        return api('POST', '/apps/' + a.app_id + '/secret/rotate').then(function (res) {
          closeModal();
          showSecretOnce('Secret rotated', res.data);
        });
      }
    );
  }

  /* ---------- One-time secret display (create/rotate) ---------- */

  function showSecretOnce(title, data) {
    var copyBtn = h('button', { class: 'btn btn-ghost btn-sm', text: 'Copy' });
    copyBtn.addEventListener('click', function () {
      if (navigator.clipboard) navigator.clipboard.writeText(data.app_secret).then(function () {
        copyBtn.textContent = 'Copied';
      });
    });
    var body = h('div', {}, [
      h('p', { class: 'form-error', style: 'margin:0 0 10px;',
               text: 'This secret is shown only once and is never returned again by the server. Copy it now and store it safely.' }),
      h('div', { class: 'field' }, [
        h('span', { class: 'field-label', text: 'App Key' }),
        h('div', { class: 'mono', text: data.app_key || ('app_' + data.app_id) })
      ]),
      h('div', { class: 'field', style: 'margin-top:10px;' }, [
        h('span', { class: 'field-label', text: 'App Secret' }),
        h('div', { class: 'secret-box', text: data.app_secret })
      ]),
      h('div', { style: 'margin-top:10px;' }, [copyBtn])
    ]);
    openModal({ title: title, body: body, actions: [
      h('button', { class: 'btn btn-primary', text: 'I have saved it', onclick: closeModal })
    ]});
  }

  /* ---------- Delete (soft delete) ---------- */

  function deleteApp(a) {
    confirmModal(
      'Delete App',
      '"' + (a.name || '') + '" will be soft-deleted (disabled immediately, no longer accessible via any API). This cannot be undone. Delete it?',
      'Delete', true,
      function () {
        return api('DELETE', '/apps/' + a.app_id).then(loadApps);
      }
    );
  }

  /* ---------- User management (admin-provisioned directory) ---------- */

  function openUsers(a) {
    var wrap = h('div', {});
    var listWrap = h('div', { class: 'cell-muted', style: 'margin-bottom:14px;min-height:20px;', text: 'Loading…' });
    var msg = h('p', { class: 'form-error', style: 'margin:10px 0 0;', hidden: true });
    var input = h('input', {
      type: 'text', maxlength: '128', spellcheck: 'false',
      autocapitalize: 'off', autocomplete: 'off',
      placeholder: 'New user ID (e.g. u_10086)'
    });
    var addBtn = h('button', { class: 'btn btn-primary btn-sm', text: 'Add User' });

    function load() {
      api('GET', '/apps/' + a.app_id + '/users').then(function (res) {
        var users = res.data.users || [];
        clear(listWrap);
        if (!users.length) {
          listWrap.appendChild(document.createTextNode('No users yet. You can pre-provision a user_id below; the app also records users automatically on upload.'));
          return;
        }
        users.forEach(function (u) {
          listWrap.appendChild(h('div', { style: 'display:flex;justify-content:space-between;gap:10px;padding:3px 0;' }, [
            h('span', { class: 'mono', text: u.user_id }),
            h('span', { class: 'cell-muted', text: fmtTs(u.created_at) })
          ]));
        });
      }).catch(function (e) {
        clear(listWrap);
        listWrap.appendChild(document.createTextNode('Failed to load: ' + e.message));
      });
    }

    addBtn.addEventListener('click', function () {
      var uid = input.value.trim();
      if (!uid) { input.focus(); return; }
      msg.hidden = true;
      api('POST', '/apps/' + a.app_id + '/users', { user_id: uid }).then(function (res) {
        input.value = '';
        msg.style.color = res.data.created ? '#2f9e44' : '#c05621';
        msg.textContent = res.data.created
          ? 'User "' + uid + '" added.'
          : 'User "' + uid + '" already exists.';
        msg.hidden = false;
        load();
      }).catch(function (e) {
        msg.style.color = '';
        msg.textContent = e.message;
        msg.hidden = false;
      });
    });

    wrap.appendChild(listWrap);
    wrap.appendChild(h('div', { style: 'display:flex;gap:8px;align-items:center;' }, [input, addBtn]));
    wrap.appendChild(msg);
    load();
    openModal({
      title: 'Users · App #' + a.app_id + (a.name ? ' — ' + a.name : ''),
      body: wrap,
      actions: [h('button', { class: 'btn btn-ghost', text: 'Close', onclick: closeModal })]
    });
  }

  /* ---------- Audit log ---------- */

  function loadAudit() {
    var wrap = document.getElementById('audit-table-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Loading…' }));

    var appId = document.getElementById('audit-app-id').value.trim();
    var since = document.getElementById('audit-since').value;
    var now = Math.floor(Date.now() / 1000);
    var qs = [];
    if (appId) qs.push('app_id=' + encodeURIComponent(appId));
    qs.push('since=' + (now - parseInt(since, 10)));

    api('GET', '/audit?' + qs.join('&')).then(function (res) {
      renderAudit(res.data.entries || []);
    }).catch(function (e) { showGlobalError(e.message); });
  }

  function renderAudit(entries) {
    var wrap = document.getElementById('audit-table-wrap');
    clear(wrap);
    if (!entries.length) {
      wrap.appendChild(h('div', { class: 'empty', text: 'No audit entries in this range.' }));
      return;
    }
    var table = h('table', {}, [
      h('thead', {}, [h('tr', {}, [
        th('Time'), th('Action'), th('App'), th('Actor'), th('Target'), th('IP'), th('Decision')
      ])]),
      h('tbody', {}, entries.map(function (e) {
        return h('tr', {}, [
          h('td', { class: 'cell-2', text: fmtTs(e.at) }),
          h('td', {}, [h('span', { class: 'mono', text: e.action || '—' })]),
          h('td', { class: 'cell-2', text: e.app_id != null ? '#' + e.app_id : '—' }),
          h('td', {}, [h('span', { class: 'mono cell-2', text: e.actor || '—' })]),
          h('td', {}, [h('span', { class: 'cell-2', text: e.target || '—' })]),
          h('td', { class: 'cell-2', text: e.ip || '—' }),
          h('td', {}, [e.decision === 'allow' ? badge('ok', 'Allow') : badge('danger', 'Deny')])
        ]);
      }))
    ]);
    wrap.appendChild(table);
  }

  /* ---------- Backup (degrades gracefully when endpoint absent) ---------- */

  function loadBackup() {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Checking backup support…' }));
    api('GET', '/backups').then(function (res) {
      renderBackupAvailable(res.data || {});
    }).catch(function (e) {
      if (e.status === 404 || e.status === 501) {
        renderBackupDisabled();
      } else {
        showGlobalError('Failed to load backup: ' + e.message);
      }
    });
  }

  function renderBackupDisabled() {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'empty', style: 'padding:48px 24px;' }, [
      h('div', { class: 'banner banner-warn', style: 'margin:0 auto 12px;max-width:420px;',
                 text: 'Not enabled yet (the backend has no /admin/v1/backups endpoint).' }),
      h('div', { class: 'cell-muted',
                 text: 'For now, back up the database and blob directory manually at the host level with sqlite3 .backup + rsync/restic.' })
    ]));
  }

  function renderBackupAvailable(data) {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    var list = (data.backups || data.entries || []);
    var statusSpan = h('span', { id: 'backup-status', class: 'cell-muted', text: '' });
    var runBtn = h('button', { class: 'btn btn-primary btn-sm', text: 'Back Up Now' });
    runBtn.addEventListener('click', function () {
      runBtn.disabled = true;
      runBtn.textContent = 'Backing up…';
      statusSpan.textContent = 'Snapshotting the database and blob storage — this may take a moment.';
      statusSpan.className = 'cell-muted';
      api('POST', '/backups/run').then(function () {
        loadBackup();
      }).catch(function (e) {
        runBtn.disabled = false;
        runBtn.textContent = 'Back Up Now';
        statusSpan.textContent = 'Backup failed: ' + e.message;
        statusSpan.className = 'banner banner-error';
        showGlobalError('Backup failed: ' + e.message);
      });
    });
    wrap.appendChild(h('div', { style: 'padding:16px 18px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;' }, [
      runBtn,
      statusSpan
    ]));
    if (!list.length) {
      wrap.appendChild(h('div', { class: 'empty', text: 'No backups yet. Run "Back Up Now" to create the first snapshot.' }));
      return;
    }
    wrap.appendChild(h('table', {}, [
      h('thead', {}, [h('tr', {}, [th('ID'), th('Status'), th('Size'), th('Finished'), th('Location')])]),
      h('tbody', {}, list.map(function (b) {
        return h('tr', {}, [
          h('td', { class: 'mono', text: String(b.id != null ? b.id : '—') }),
          h('td', {}, [h('span', { class: 'cell-2', text: b.status || '—' })]),
          h('td', { class: 'cell-2', text: fmtBytes(b.size) }),
          h('td', { class: 'cell-2', text: fmtTs(b.finished_at || b.created_at) }),
          h('td', { class: 'mono cell-muted', style: 'font-size:11.5px;word-break:break-all;', text: b.path || '—' })
        ]);
      }))
    ]));
  }

  /* ---------- Init ---------- */

  function init() {
    initLogin();

    document.querySelectorAll('#side-nav .nav-item').forEach(function (b) {
      b.addEventListener('click', function () {
        var v = b.dataset.view;
        switchView(v);
        if (v === 'apps') loadApps();
        else if (v === 'audit') loadAudit();
        else if (v === 'backup') loadBackup();
      });
    });
    document.getElementById('audit-refresh').addEventListener('click', loadAudit);

    if (token()) {
      afterLogin();
    } else {
      /* index.html ships both views `hidden`; once CSS enforces `hidden`,
         the login view must be shown explicitly for the no-token case. */
      document.getElementById('view-login').hidden = false;
      document.getElementById('app-shell').hidden = true;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
