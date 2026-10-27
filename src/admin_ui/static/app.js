/* ============================================================
 * 管理控制台前端邏輯（純手寫、零依賴、零外部請求）
 *
 * 安全模型：
 *  - 管理員權杖僅存 sessionStorage，不進 localStorage / URL / cookie。
 *  - 所有 API 回傳資料一律以 textContent / DOM 屬性渲染，
 *    全程不對不可信資料使用 innerHTML（見 INTEGRATION.md 核對清單）。
 *  - app_secret 只在「建立 / 輪換」成功後一次性展示，此後不再載入頁面。
 * ============================================================
 */
(function () {
  'use strict';

  var TOKEN_KEY = 'fs_admin_token';

  /* API 基底：相對於本頁位置解析。
   * 頁面若掛在 /admin/ 或 /admin/index.html，此處解析出 /admin/v1/，
   * 與 admin_router 的 /admin/v1/* 同源，無須硬編碼主機埠號。 */
  var API_BASE = new URL('v1/', document.baseURI).pathname.replace(/\/$/, '');

  /* ---------- 小型 DOM 工具（不使用 innerHTML 渲染資料） ---------- */

  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'html') el.innerHTML = v; /* 僅供靜態骨架，不夾使用者資料 */
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

  /* ---------- 格式化 ---------- */

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

  /* ---------- API 呼叫 ---------- */

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
      if (res.status === 401) { doLogout(); throw new ApiError(401, 'unauthorized', '權杖無效或已過期，請重新登入。'); }
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

  /* ---------- 通用 UI 元件 ---------- */

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
        h('button', { class: 'btn btn-ghost', text: '取消', onclick: closeModal }),
        btn
      ]
    });
  }

  function badge(status, label) {
    return h('span', { class: 'badge badge-' + status, text: label });
  }

  /* ---------- 登入 / 登出 ---------- */

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
        errEl.textContent = (err.status === 401) ? '權杖不正確，登入失敗。' : ('無法連接管理 API：' + err.message);
        errEl.hidden = false;
      });
    });
    document.getElementById('btn-logout').addEventListener('click', doLogout);
  }

  /* ---------- 視圖切換 ---------- */

  var VIEW_TITLES = { apps: '應用程式', audit: '稽核記錄', backup: '備份' };
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
        class: 'btn btn-primary', text: '建立應用程式', onclick: openCreateAppModal
      }));
    } else if (currentView === 'audit') {
      wrap.appendChild(h('button', {
        class: 'btn btn-ghost', text: '重新整理', onclick: loadAudit
      }));
    }
  }

  /* ---------- 應用程式列表 ---------- */

  function loadApps() {
    var wrap = document.getElementById('apps-table-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: '載入中…' }));
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
      wrap.appendChild(h('div', { class: 'empty', text: '尚無應用程式，按右上角「建立應用程式」新增。' }));
      return;
    }

    var table = h('table', {}, [
      h('thead', {}, [h('tr', {}, [
        th('應用程式'), th('App Key'), th('狀態'),
        th('用量'), th('配額'), th('單檔上限'), th('建立時間'), th('操作', 'right')
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
    var statusBadge = deleted ? badge('danger', '已刪除')
      : a.enabled ? badge('ok', '啟用中') : badge('warn', '已停用');

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
      h('button', { class: 'btn btn-ghost btn-sm', text: '用量', onclick: function () { openUsage(a.app_id); } }),
      deleted ? null : h('button', {
        class: 'btn btn-ghost btn-sm',
        text: a.enabled ? '停用' : '啟用',
        onclick: function () { toggleApp(a); }
      }),
      deleted ? null : h('button', {
        class: 'btn btn-ghost btn-sm', text: '輪換密鑰',
        onclick: function () { openRotate(a); }
      }),
      deleted ? null : h('button', {
        class: 'btn btn-danger-ghost btn-sm', text: '刪除',
        onclick: function () { deleteApp(a); }
      })
    ]);

    return h('tr', {}, [
      h('td', {}, [
        h('div', { text: a.name || '(未命名)' }),
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

  /* ---------- 建立應用程式 ---------- */

  function openCreateAppModal() {
    var nameI = h('input', { type: 'text', required: true, maxlength: '120', placeholder: '例如：客服後台' });
    var quotaGiB = h('input', { type: 'number', min: '1', step: '1', value: '10' });
    var maxMiB = h('input', { type: 'number', min: '1', step: '1', value: '100' });

    var body = h('div', {}, [
      field('應用程式名稱', nameI),
      field('儲存配額（GiB，1 GiB = 1024³ B）', quotaGiB),
      field('單檔上限（MiB）', maxMiB)
    ]);

    var submit = h('button', {
      class: 'btn btn-primary', text: '建立',
      onclick: function () {
        var name = nameI.value.trim();
        if (!name) { nameI.focus(); return; }
        var quota = parseInt(quotaGiB.value, 10) * 1024 * 1024 * 1024;
        var maxp = parseInt(maxMiB.value, 10) * 1024 * 1024;
        if (!quota || quota <= 0 || !maxp || maxp <= 0) { showGlobalError('配額與單檔上限必須為正整數。'); return; }
        api('POST', '/apps', { name: name, quota_bytes: quota, max_payload_bytes: maxp }).then(function (res) {
          closeModal();
          showSecretOnce('建立成功', res.data);
          loadApps();
        }).catch(function (e) { showGlobalError(e.message); });
      }
    });

    openModal({ title: '建立應用程式', body: body, actions: [
      h('button', { class: 'btn btn-ghost', text: '取消', onclick: closeModal }), submit
    ]});
  }

  function field(label, inputEl) {
    return h('label', { class: 'field' }, [
      h('span', { class: 'field-label', text: label }), inputEl
    ]);
  }

  /* ---------- 用量明細 ---------- */

  function openUsage(id) {
    api('GET', '/apps/' + id + '/usage').then(function (res) {
      var u = res.data;
      var rows = [
        ['已用空間', fmtBytes(u.usage_bytes)],
        ['儲存配額', fmtBytes(u.quota_bytes)],
        ['檔案數量', String(u.file_count)],
        ['有效下載令牌', String(u.active_token_count)]
      ];
      var body = h('table', {}, [h('tbody', {}, rows.map(function (r) {
        return h('tr', {}, [
          h('td', { class: 'cell-2', text: r[0] }),
          h('td', { class: 'mono', text: r[1] })
        ]);
      }))]);
      openModal({ title: '用量明細 · App #' + id, body: body, actions: [
        h('button', { class: 'btn btn-ghost', text: '關閉', onclick: closeModal })
      ]});
    }).catch(function (e) { showGlobalError(e.message); });
  }

  /* ---------- 啟用 / 停用 ---------- */

  function toggleApp(a) {
    var next = !a.enabled;
    confirmModal(
      next ? '啟用應用程式' : '停用應用程式',
      next ? '確定要重新啟用「' + (a.name || '') + '」嗎？'
           : '停用後該 App 的所有上傳／下載／令牌簽署將立即拒絕。確定停用？',
      next ? '啟用' : '停用', !next,
      function () {
        return api('PATCH', '/apps/' + a.app_id, { enabled: next }).then(loadApps);
      }
    );
  }

  /* ---------- 輪換密鑰 ---------- */

  function openRotate(a) {
    confirmModal(
      '輪換 App Secret',
      '輪換後「' + (a.name || '') + '」的舊 secret 立即失效，所有以舊 secret 簽發的 HMAC 與使用者 JWT 都會失敗。請確定後端已可同步更新。',
      '確定輪換', true,
      function () {
        return api('POST', '/apps/' + a.app_id + '/secret/rotate').then(function (res) {
          closeModal();
          showSecretOnce('輪換成功', res.data);
        });
      }
    );
  }

  /* ---------- 一次性展示 secret（建立／輪換共用） ---------- */

  function showSecretOnce(title, data) {
    var copyBtn = h('button', { class: 'btn btn-ghost btn-sm', text: '複製' });
    copyBtn.addEventListener('click', function () {
      if (navigator.clipboard) navigator.clipboard.writeText(data.app_secret).then(function () {
        copyBtn.textContent = '已複製';
      });
    });
    var body = h('div', {}, [
      h('p', { class: 'form-error', style: 'margin:0 0 10px;',
               text: '此 secret 只會顯示這一次，伺服器不再回傳，請立即複製並妥善保存。' }),
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
      h('button', { class: 'btn btn-primary', text: '我已妥善保存', onclick: closeModal })
    ]});
  }

  /* ---------- 刪除（軟刪除） ---------- */

  function deleteApp(a) {
    confirmModal(
      '刪除應用程式',
      '「' + (a.name || '') + '」將被軟刪除（立即停用、不再可被任何 API 存取）。此動作不可恢復。確定刪除？',
      '確定刪除', true,
      function () {
        return api('DELETE', '/apps/' + a.app_id).then(loadApps);
      }
    );
  }

  /* ---------- 稽核記錄 ---------- */

  function loadAudit() {
    var wrap = document.getElementById('audit-table-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: '載入中…' }));

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
      wrap.appendChild(h('div', { class: 'empty', text: '此範圍內沒有稽核紀錄。' }));
      return;
    }
    var table = h('table', {}, [
      h('thead', {}, [h('tr', {}, [
        th('時間'), th('動作'), th('App'), th('主體'), th('目標'), th('IP'), th('判決')
      ])]),
      h('tbody', {}, entries.map(function (e) {
        return h('tr', {}, [
          h('td', { class: 'cell-2', text: fmtTs(e.at) }),
          h('td', {}, [h('span', { class: 'mono', text: e.action || '—' })]),
          h('td', { class: 'cell-2', text: e.app_id != null ? '#' + e.app_id : '—' }),
          h('td', {}, [h('span', { class: 'mono cell-2', text: e.actor || '—' })]),
          h('td', {}, [h('span', { class: 'cell-2', text: e.target || '—' })]),
          h('td', { class: 'cell-2', text: e.ip || '—' }),
          h('td', {}, [e.decision === 'allow' ? badge('ok', '允許') : badge('danger', '拒絕')])
        ]);
      }))
    ]);
    wrap.appendChild(table);
  }

  /* ---------- 備份（端點未實作時優雅降級） ---------- */

  function loadBackup() {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: '檢查備份功能…' }));
    api('GET', '/backups').then(function (res) {
      renderBackupAvailable(res.data || {});
    }).catch(function (e) {
      if (e.status === 404 || e.status === 501) {
        renderBackupDisabled();
      } else {
        showGlobalError('備份功能載入失敗：' + e.message);
      }
    });
  }

  function renderBackupDisabled() {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'empty', style: 'padding:48px 24px;' }, [
      h('div', { class: 'banner banner-warn', style: 'margin:0 auto 12px;max-width:420px;',
                 text: '此功能尚未啟用（後端尚無 /admin/v1/backups 端點）。' }),
      h('div', { class: 'cell-muted',
                 text: '目前請於伺服器本機層以 sqlite3 .backup + rsync/restic 手動備份資料庫與 blob 目錄。' })
    ]));
  }

  function renderBackupAvailable(data) {
    var wrap = document.getElementById('backup-wrap');
    clear(wrap);
    var list = (data.backups || data.entries || []);
    wrap.appendChild(h('div', { style: 'padding:16px 18px;display:flex;gap:8px;align-items:center;' }, [
      h('button', { class: 'btn btn-primary btn-sm', text: '立即備份', onclick: function () {
        api('POST', '/backups/run').then(loadBackup).catch(function (e) { showGlobalError(e.message); });
      }}),
      h('span', { class: 'cell-muted', text: '規範定義但仍可能隨版本變動' })
    ]));
    if (!list.length) {
      wrap.appendChild(h('div', { class: 'empty', text: '尚無備份紀錄。' }));
      return;
    }
    wrap.appendChild(h('table', {}, [
      h('thead', {}, [h('tr', {}, [th('ID'), th('狀態'), th('大小'), th('完成時間')])]),
      h('tbody', {}, list.map(function (b) {
        return h('tr', {}, [
          h('td', { class: 'mono', text: String(b.id != null ? b.id : '—') }),
          h('td', {}, [h('span', { class: 'cell-2', text: b.status || '—' })]),
          h('td', { class: 'cell-2', text: fmtBytes(b.size) }),
          h('td', { class: 'cell-2', text: fmtTs(b.finished_at || b.created_at) })
        ]);
      }))
    ]));
  }

  /* ---------- 初始化 ---------- */

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

    if (token()) { afterLogin(); }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
