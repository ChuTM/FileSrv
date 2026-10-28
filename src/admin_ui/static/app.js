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
  window.__APPJS = 'v3-motion';

  /* ---------- Motion (GSAP, reduced-motion aware) ----------
   * Weighting: Emil (restraint, sub-300ms) with Jakub polish. Motion is gated
   * by frequency — a single orchestrated shell entry, short view transitions,
   * a one-time stagger on freshly rendered rows, and a modal sheet. All of it
   * collapses to zero duration under prefers-reduced-motion.
   *
   * GSAP normally arrives at window.gsap via <script src="gsap.min.js">, but
   * some sandboxed webviews run external scripts in an isolated global. G()
   * therefore self-bootstraps from the same self-hosted file as a fallback. */
  function G() {
    if (window.gsap) return window.gsap;
    try {
      var x = new XMLHttpRequest();
      x.open('GET', new URL('gsap.min.js', document.baseURI).href, false);
      x.send();
      if (x.status === 200 && x.responseText) { (0, eval)(x.responseText); return window.gsap || null; }
    } catch (e) {}
    return null;
  }
  function reduceMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }
  function viewEnter(el) {
    var gsap = G(); if (!gsap) return;
    gsap.fromTo(el,
      { autoAlpha: 0, y: 10, filter: 'blur(6px)' },
      { autoAlpha: 1, y: 0, filter: 'blur(0px)', duration: reduceMotion() ? 0 : 0.24, ease: 'power2.out', clearProps: 'all' });
  }
  function rowsEnter(table) {
    var gsap = G(); if (!gsap) return;
    var rows = table.querySelectorAll('tbody tr');
    if (!rows.length) return;
    gsap.fromTo(rows,
      { autoAlpha: 0, y: 6 },
      { autoAlpha: 1, y: 0, duration: reduceMotion() ? 0 : 0.22, stagger: reduceMotion() ? 0 : 0.025, ease: 'power2.out', clearProps: 'all' });
  }
  function shellEnter() {
    var gsap = G(); if (!gsap) return;
    var d = reduceMotion() ? 0 : 0.4;
    // The sidebar is an off-canvas drawer: leave its closed CSS transform
    // (translateX(-104%)) alone so it stays hidden until the hamburger opens it.
    var mainEl = document.querySelector('.main');
    if (mainEl) gsap.fromTo(mainEl,
      { y: 14, autoAlpha: 0, filter: 'blur(8px)' },
      { y: 0, autoAlpha: 1, filter: 'blur(0px)', duration: d + 0.05, delay: 0.06, ease: 'power2.out', clearProps: 'all' });
  }

  /* API base: the admin API always lives at /admin/v1/* on the loopback admin
   * bind. It is pinned (not derived from the page path) so both the login page
   * (/admin/) and every dashboard page (/dashboard/apps, …) — which live under
   * a different URL prefix — reach the same bearer-authenticated endpoints. */
  var API_BASE = '/admin/v1';

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

  function clear(node) { if (!node) return; while (node.firstChild) node.removeChild(node.firstChild); }

  /* Lucide icons — self-contained 24px stroke-based SVG bodies, no font, no
     external fetch, no emoji. CSP-safe (inline SVG, no network). */
  var SVGNS = 'http://www.w3.org/2000/svg';
  var ICONS = {
    menu: '<line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/>',
    close: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    apps: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    audit: '<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>',
    backup: '<path d="M12 13v8"/><path d="M4 17a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2"/><polyline points="8 17 12 21 16 17"/>',
    archive: '<rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>',
    settings: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    usage: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
    disable: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
    enable: '<polygon points="6 3 20 12 6 21 6 3"/>',
    rotate: '<path d="m15.5 7.5 3 3L22 7l-3-3"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/>',
    unarchive: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
    wipe: '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>',
    recompute: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
    audit_file: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    more_h: '<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>'
  };

  function icon(name, size, cls) {
    var s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('width', size || 16);
    s.setAttribute('height', size || 16);
    s.setAttribute('aria-hidden', 'true');
    if (cls) s.setAttribute('class', cls);
    s.setAttribute('fill', 'none');
    s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '2');
    s.setAttribute('stroke-linecap', 'round');
    s.setAttribute('stroke-linejoin', 'round');
    s.innerHTML = ICONS[name] || '';
    return s;
  }

  /* Replace every <span data-icon="name"> with its inline SVG (used by the
   * static nav/footer markup). */
  function fillIcons(root) {
    var els = (root || document).querySelectorAll('[data-icon]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var ic = icon(el.getAttribute('data-icon'));
      if (el.parentNode) el.parentNode.replaceChild(ic, el);
    }
  }

  /* Icon + label action button (row actions are horizontal, not stacked). */
  function actionBtn(iconName, label, onclick, cls) {
    return h('button', {
      class: 'btn btn-ghost btn-sm' + (cls ? ' ' + cls : ''),
      onclick: onclick
    }, [
      icon(iconName, 14), h('span', { text: label })
    ]);
  }

  /* Row action menu — a single ⋮ trigger that opens a stacked dropdown with
     the per-app actions. Keeps the table row clean; no emoji, all Lucide. */
  function actionMenu(items) {
    var menu = h('div', { class: 'row-menu' });
    items.forEach(function (it) {
      menu.appendChild(h('button', { class: 'menu-item' + (it.danger ? ' danger' : ''), onclick: function () {
        closeMenus();
        it.onclick();
      } }, [icon(it.icon, 16), h('span', { text: it.label })]));
    });
    var btn = h('button', { class: 'icon-btn menu-trigger', title: 'Actions', 'aria-label': 'Actions' },
      [icon('more_h', 18)]);
    btn.onclick = function () { openRowMenu(btn, menu); };   /* native property — most reliable */
    var anchor = h('div', { class: 'menu-anchor' }, [btn, menu]);
    return anchor;
  }
  /* Named rowMenuToggle (not toggleMenu) to avoid clashing with the sidebar
     hamburger's toggleMenu below — function declarations are hoisted, so a
     later `function toggleMenu()` would shadow this one. */
  function rowMenuToggle(menu) {
    var anyOpen = menu.classList.contains('open');
    closeMenus();
    if (!anyOpen) menu.classList.add('open');
  }
  /* Open the ⋮ row menu pinned to the trigger. The menu is position:fixed so it
     escapes the table's overflow clipping; we place it from the trigger's
     bounding box and flip it above when there is no room below the viewport. */
  function openRowMenu(btn, menu) {
    if (menu.classList.contains('open')) { closeMenus(); return; }
    closeMenus();
    var r = btn.getBoundingClientRect();
    var w = menu.offsetWidth || 184;
    var h = menu.offsetHeight || 176;
    var below = window.innerHeight - r.bottom;
    var top = (below < h + 12) ? Math.max(8, r.top - h - 6) : (r.bottom + 6);
    menu.style.top = top + 'px';
    menu.style.left = Math.max(8, r.right - w) + 'px';
    /* Belt-and-braces: force the visible final state inline too. The CSS
       `.row-menu.open` transition handles the fade in normal browsers; setting
       the inline values guarantees the menu shows even where a CSS class
       transition never runs (e.g. paused/headless renderers). */
    menu.style.opacity = '1';
    menu.style.visibility = 'visible';
    menu.style.transform = 'none';
    menu.classList.add('open');
  }
  function closeMenus() {
    document.querySelectorAll('.row-menu.open').forEach(function (m) {
      m.classList.remove('open');
      m.style.opacity = '';
      m.style.visibility = '';
      m.style.transform = '';
    });
  }
  /* Close open menus when clicking outside an open menu-anchor. The ⋮ trigger
     and its menu items carry their own handlers, so we never toggle here. */
  document.addEventListener('click', function (e) {
    if (!e.target.closest || !e.target.closest('.menu-anchor')) closeMenus();
  });
  /* Menus are position:fixed relative to the viewport, so any scroll (table
     overflow or the page) would leave them floating in the wrong place — close
     them on scroll. */
  window.addEventListener('scroll', closeMenus, true);

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
    var gsap = G(); if (gsap) {
      var d = reduceMotion() ? 0 : 0.2;
      gsap.fromTo(overlay, { autoAlpha: 0 }, { autoAlpha: 1, duration: d, ease: 'power2.out' });
      gsap.fromTo(card, { autoAlpha: 0, y: 14, scale: 0.97, transformOrigin: '50% 100%' },
        { autoAlpha: 1, y: 0, scale: 1, duration: d + 0.04, ease: 'power2.out' });
    }
    return { overlay: overlay, card: card };
  }

  function closeModal() {
    var root = document.getElementById('modal-root');
    var card = root.querySelector('.modal');
    var overlay = root.querySelector('.modal-overlay');
    var gsap = G(); if (!card || !gsap) { clear(root); return; }
    var d = reduceMotion() ? 0 : 0.14;
    gsap.to(card, { autoAlpha: 0, y: 8, scale: 0.98, duration: d, ease: 'power2.in', overwrite: true,
      onComplete: function () { clear(root); } });
    gsap.to(overlay, { autoAlpha: 0, duration: d, ease: 'power2.in', overwrite: true });
  }

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

  /* ---------- Login / logout (multi-page) ---------- */

  function doLogout() {
    sessionStorage.removeItem(TOKEN_KEY);
    window.location.href = '/admin/login.html';
  }

  function initLogin() {
    var form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = document.getElementById('login-token');
      var errEl = document.getElementById('login-error');
      var t = input.value.trim();
      if (!t) return;
      sessionStorage.setItem(TOKEN_KEY, t);
      api('GET', '/apps').then(function () {
        window.location.href = '/dashboard/apps';
      }).catch(function (err) {
        sessionStorage.removeItem(TOKEN_KEY);
        errEl.textContent = (err.status === 401) ? 'Invalid token. Sign-in failed.' : ('Cannot reach the admin API: ' + err.message);
        errEl.hidden = false;
      });
    });
  }

  /* ---------- Multi-page init helpers ---------- */

  var appsStatusFilter = 'all'; // 'all' | 'active' | 'disabled' — for the Apps list

  function guardToken() {
    if (!sessionStorage.getItem(TOKEN_KEY)) {
      window.location.replace('/admin/login.html');
      return false;
    }
    return true;
  }

  function bindClick(id, fn) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', fn);
  }

  function toggleMenu() {
    var sb = document.getElementById('sidebar');
    if (!sb) return;
    var open = sb.classList.toggle('open');
    var sc = document.getElementById('scrim');
    if (sc) sc.hidden = !open;
  }
  function closeMenu() {
    var sb = document.getElementById('sidebar');
    if (sb) sb.classList.remove('open');
    var sc = document.getElementById('scrim');
    if (sc) sc.hidden = true;
  }

  function initShellPage(page) {
    bindClick('btn-logout', doLogout);
    bindClick('btn-menu', toggleMenu);
    bindClick('scrim', closeMenu);
    fillIcons(document);
    var shell = document.getElementById('app-shell');
    if (shell) shellEnter(shell);
    var view = document.querySelector('.view');
    if (view) viewEnter(view);
    if (page === 'apps') {
      bindClick('btn-create-app', openCreateAppModal);
      loadApps();
    } else if (page === 'audit') {
      bindClick('audit-refresh', loadAudit);
      loadAudit();
    } else if (page === 'backup') {
      loadBackup();
    } else if (page === 'archive') {
      bindClick('btn-archive-refresh', loadArchiveApps);
      loadArchiveApps();
    } else if (page === 'settings') {
      bindClick('btn-settings-refresh', loadSettings);
      loadSettings();
    }
  }

  /* ---------- App list ---------- */

  function loadApps() {
    var wrap = document.getElementById('apps-table-wrap');
    if (!wrap) return;   // not on the Apps page right now — nothing to refresh here
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/apps').then(function (res) {
      // Non-archived apps live in the main Apps list; archived apps are shown
      // in the separate "Archive" view where they can be unarchived or wiped.
      var all = (res.data.apps || []).filter(function (a) { return !a.deleted_at; });
      var shown = all.filter(function (a) {
        if (appsStatusFilter === 'active') return !!a.enabled;
        if (appsStatusFilter === 'disabled') return !a.enabled;
        return true; // 'all'
      });
      renderApps(shown, all.length);
    }).catch(function (e) {
      showGlobalError(e.message);
    });
  }

  function renderApps(apps, totalAll) {
    var wrap = document.getElementById('apps-table-wrap');
    clear(wrap);

    var filterBar = h('div', { class: 'filter-bar', style: 'margin-bottom:12px;' }, [
      h('label', { class: 'field inline' }, [
        h('span', { class: 'field-label', text: 'Status' }),
        h('select', {
          id: 'apps-status-filter',
          value: appsStatusFilter,
          onchange: function () { appsStatusFilter = this.value; loadApps(); }
        }, [
          h('option', { value: 'all', text: 'All (' + (totalAll || 0) + ')' }),
          h('option', { value: 'active', text: 'Active' }),
          h('option', { value: 'disabled', text: 'Disabled' })
        ])
      ])
    ]);
    wrap.appendChild(filterBar);

    if (!apps.length) {
      wrap.appendChild(h('div', { class: 'empty', text: appsStatusFilter === 'all'
        ? 'No apps yet. Use "Create App" in the top-right corner.'
        : 'No apps with this status in this filter.' }));
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
    rowsEnter(table);
  }

  function th(text, align) {
    return h('th', align === 'right' ? { class: 'num', text: text } : { text: text });
  }

  function appRow(a) {
    var deleted = !!a.deleted_at;
    var statusBadge = deleted ? badge('danger', 'Deleted')
      : a.enabled ? badge('ok', 'Active') : badge('neutral', 'Disabled');

    var pct = (a.quota_bytes > 0 && a.usage_bytes != null)
      ? Math.min(100, Math.round(a.usage_bytes / a.quota_bytes * 100)) : null;
    var fillCls = pct == null ? '' : (pct >= 100 ? ' full' : pct >= 80 ? ' hot' : '');

    var usageCell = h('div', { class: 'quota' }, [
      h('span', { text: fmtBytes(a.usage_bytes) }),
      h('div', { class: 'quota-bar' }, [
        h('div', { class: 'quota-fill' + fillCls, style: 'width:' + (pct || 0) + '%' })
      ])
    ]);

    var actions = actionMenu([
      { icon: 'usage', label: 'Usage', onclick: function () { openUsage(a.app_id); } },
      { icon: 'users', label: 'Users', onclick: function () { openUsers(a); } },
      { icon: a.enabled ? 'disable' : 'enable', label: a.enabled ? 'Disable' : 'Enable', onclick: function () { toggleApp(a); } },
      { icon: 'rotate', label: 'Rotate', onclick: function () { openRotate(a); } },
      { icon: 'archive', label: 'Archive', onclick: function () { archiveApp(a); } }
    ]);

    return h('tr', { class: a.enabled && !deleted ? '' : 'row-muted' }, [
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

  /* ---------- Archive (soft-deleted apps) view ---------- */

  function loadArchiveApps() {
    var wrap = document.getElementById('archive-table-wrap');
    if (!wrap) return;   // not on the Archive page right now — nothing to refresh here
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/apps').then(function (res) {
      renderArchiveApps((res.data.apps || []).filter(function (a) { return !!a.deleted_at; }));
    }).catch(function (e) {
      showGlobalError(e.message);
    });
  }

  function renderArchiveApps(apps) {
    var wrap = document.getElementById('archive-table-wrap');
    clear(wrap);
    if (!apps.length) {
      wrap.appendChild(h('div', { class: 'empty', text: 'The archive is empty. Archived apps appear here.' }));
      return;
    }
    var table = h('table', {}, [
      h('thead', {}, [h('tr', {}, [
        th('App'), th('App Key'), th('Usage'), th('Created'), th('Archived'), th('Actions', 'right')
      ])]),
      h('tbody', {}, apps.map(function (a) { return archiveAppRow(a); }))
    ]);
    wrap.appendChild(table);
    rowsEnter(table);
  }

  function archiveAppRow(a) {
    var actions = actionMenu([
      { icon: 'unarchive', label: 'Unarchive', onclick: function () { unarchiveApp(a); } },
      { icon: 'wipe', label: 'Wipe out', danger: true, onclick: function () { wipeApp(a); } }
    ]);
    return h('tr', {}, [
      h('td', {}, [
        h('div', { text: a.name || '(unnamed)' }),
        h('div', { class: 'cell-muted', text: 'ID #' + a.app_id })
      ]),
      h('td', {}, [h('span', { class: 'mono cell-2', text: a.app_key || '—' })]),
      h('td', { class: 'cell-2', text: fmtBytes(a.usage_bytes) }),
      h('td', { class: 'cell-2', text: fmtTs(a.created_at) }),
      h('td', { class: 'cell-2', text: fmtTs(a.deleted_at) }),
      h('td', { class: 'num' }, [actions])
    ]);
  }

  function unarchiveApp(a) {
    confirmModal(
      'Unarchive App',
      'Unarchive "' + (a.name || '') + '" (ID #' + a.app_id + ')? It is re-enabled and moves back to the Apps list. ' +
        'Note: file CONTENT may already be gone if the blobs were wiped earlier — only metadata is guaranteed.',
      'Unarchive', false,
      function () {
        return api('POST', '/apps/' + a.app_id + '/unarchive').then(function () {
          loadApps(); loadArchiveApps();
        });
      }
    );
  }

  function wipeApp(a) {
    confirmModal(
      'Wipe Out App',
      'Wipe out "' + (a.name || '') + '" (ID #' + a.app_id + ')?\n\n' +
        'This removes the app record and ALL of its files, tokens, users and groups metadata, ' +
        'and physically deletes the on-disk blob directory. THIS CANNOT BE UNDONE and frees its storage.',
      'Wipe out', true,
      function () {
        return api('POST', '/apps/' + a.app_id + '/wipe').then(function () {
          loadApps(); loadArchiveApps();
        });
      }
    );
  }

  function archiveApp(a) {
    confirmModal(
      'Archive App',
      'Archive "' + (a.name || '') + '" (ID #' + a.app_id + ')?\n\n' +
        'It is disabled immediately and moved to the Archive view. File content stays on disk until you wipe it. ' +
        'This can be undone with Unarchive.',
      'Archive', false,
      function () {
        return api('POST', '/apps/' + a.app_id + '/archive').then(loadApps);
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
    rowsEnter(table);
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
    var page = document.body.getAttribute('data-page') || '';
    if (page === 'login') {
      initLogin();
      return;
    }
    if (!guardToken()) return;
    initShellPage(page);
  }

  /* ---------- Settings (storage / audit / backup) ---------- */

  function loadSettings() {
    var wrap = document.getElementById('settings-wrap');
    clear(wrap);
    wrap.appendChild(h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/storage/info').then(function (res) {
      renderSettings(res.data || {});
    }).catch(function (e) {
      showGlobalError(e.message);
    });
  }

  function statCard(label, value, sub) {
    var box = h('div', { class: 'table-card', style: 'padding:12px 16px;min-width:150px;' }, [
      h('div', { style: 'font-size:22px;font-weight:600;', text: value == null ? '—' : String(value) }),
      h('div', { style: 'color:#6b7280;font-size:12px;margin-top:2px;', text: label }),
      sub ? h('div', { style: 'color:#9ca3af;font-size:11px;margin-top:2px;', text: sub }) : null
    ]);
    return box;
  }

  function kvRow(k, v) {
    return h('div', { style: 'display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid rgba(0,0,0,.06);' }, [
      h('span', { style: 'color:#6b7280;', text: k }),
      h('span', { class: 'mono', style: 'color:#111827;', text: v })
    ]);
  }

  function renderSettings(s) {
    var wrap = document.getElementById('settings-wrap');
    clear(wrap);

    var apps = s.apps || {};
    var files = s.files || {};
    var db = s.db || {};
    var blobs = s.blobs || {};
    var backup = s.backup || {};
    var mnt = s.maintenance || {};

    // ---- storage maintenance actions ----
    var resultEl = h('pre', { class: 'audit-result', style: 'white-space:pre-wrap;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:10px;font-size:12px;margin:10px 0 0;', hidden: true });
    var runRecompute = h('button', { class: 'btn btn-primary', onclick: function () {
      var btn = runRecompute; btn.disabled = true; resultEl.hidden = false; resultEl.textContent = 'Recomputing…';
      api('POST', '/storage/recompute').then(function (res) {
        resultEl.textContent = 'usage_bytes recomputed for ' + (res.data.recomputed || 0) + ' app(s):\n' +
          JSON.stringify(res.data.apps || [], null, 2);
        btn.disabled = false;
      }).catch(function (e) { resultEl.textContent = 'Error: ' + e.message; btn.disabled = false; });
    } }, [icon('recompute', 14), h('span', { text: 'Recompute usage' })]);
    var runAudit = h('button', { class: 'btn btn-ghost', onclick: function () {
      var btn = runAudit; btn.disabled = true; resultEl.hidden = false; resultEl.textContent = 'Auditing… (reads blob files, may take a while)';
      api('POST', '/storage/audit').then(function (res) {
        var d = res.data || {};
        var lines = ['Audit result:', '  checked: ' + d.checked, '  ok: ' + d.ok,
          '  missing: ' + d.missing, '  size_mismatch: ' + d.size_mismatch, '  sha_mismatch: ' + d.sha_mismatch,
          '  bytes_ok: ' + fmtBytes(d.bytes_ok)];
        if (d.missing_sample && d.missing_sample.length) {
          lines.push('', 'Missing sample:'); lines.push.apply(lines, d.missing_sample.slice(0, 15).map(function (x) { return '  ' + x; }));
        }
        if (d.size_sample && d.size_sample.length) {
          lines.push('', 'Size mismatch sample:'); lines.push.apply(lines, d.size_sample.slice(0, 10).map(function (x) { return '  ' + x; }));
        }
        resultEl.textContent = lines.join('\n');
        btn.disabled = false;
      }).catch(function (e) { resultEl.textContent = 'Error: ' + e.message; btn.disabled = false; });
    } }, [icon('audit_file', 14), h('span', { text: 'Audit files (integrity)' })]);

    var opsCard = h('div', { class: 'table-card', style: 'padding:16px;' }, [
      h('h3', { style: 'margin:0 0 6px;', text: 'Storage Maintenance' }),
      h('p', { class: 'cell-muted', style: 'margin:0;', text: 'Recompute usage counters from the live file rows, or run a full integrity audit of the blobs on disk (existence, size, SHA-256).' }),
      h('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 0;' }, [runRecompute, runAudit]),
      resultEl
    ]);

    // ---- overview stats ----
    var quotaPct = s.quota_bytes > 0 ? Math.round((s.usage_bytes / s.quota_bytes) * 100) : 0;
    var overview = h('div', { class: 'stat-grid', style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:12px 0;' }, [
      statCard('Apps total', apps.total),
      statCard('Active', apps.active),
      statCard('Disabled', apps.disabled),
      statCard('Archived', apps.archived),
      statCard('Files (live)', files.live),
      statCard('Files (all)', files.total),
      statCard('Usage', fmtBytes(s.usage_bytes), quotaPct + '% of quota'),
      statCard('Quota', fmtBytes(s.quota_bytes)),
      statCard('Blob store', fmtBytes(blobs.bytes), blobs.path),
      statCard('Database', fmtBytes(db.bytes), db.path)
    ]);

    // ---- backup details ----
    var backupCard = h('div', { class: 'table-card', style: 'padding:16px;margin-bottom:12px;' }, [
      h('h3', { style: 'margin:0 0 6px;', text: 'Backup' }),
      kvRow('Root', backup.root || '—'),
      kvRow('Copies kept', String(backup.count)),
      kvRow('Retention', (backup.retention == null ? '—' : backup.retention + ' copies')),
      kvRow('Backup bytes', fmtBytes(backup.bytes)),
      kvRow('Last backup id', backup.last_id || '—'),
      kvRow('Last backup status', backup.last_status || '—'),
      kvRow('Last backup at', backup.last_created_at ? fmtTs(backup.last_created_at) : '—')
    ]);

    // ---- maintenance / retention details ----
    var mntCard = h('div', { class: 'table-card', style: 'padding:16px;' }, [
      h('h3', { style: 'margin:0 0 6px;', text: 'Maintenance / Retention' }),
      kvRow('Soft-delete grace (s)', String(mnt.soft_delete_grace_secs)),
      kvRow('Purge interval (s)', String(mnt.purge_interval_secs)),
      kvRow('Audit retention (s)', String(mnt.audit_retention_secs))
    ]);

    wrap.appendChild(opsCard);
    wrap.appendChild(overview);
    wrap.appendChild(backupCard);
    wrap.appendChild(mntCard);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
