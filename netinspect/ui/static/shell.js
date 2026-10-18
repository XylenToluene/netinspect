/* netinspect: общий каркас страниц — переключатель темы и статус подключения в сайдбаре. */
(function () {
  'use strict';
  var KEY = 'netinspect-theme';

  function stored() {
    try { return window.localStorage.getItem(KEY) || 'system'; } catch (e) { return 'system'; }
  }
  function applyTheme(value) {
    var root = document.documentElement;
    if (value === 'light' || value === 'dark') root.setAttribute('data-theme', value);
    else root.removeAttribute('data-theme');
    try {
      if (value === 'system') window.localStorage.removeItem(KEY);
      else window.localStorage.setItem(KEY, value);
    } catch (e) { /* без сохранения */ }
    Array.prototype.forEach.call(document.querySelectorAll('[data-theme-value]'), function (b) {
      b.setAttribute('aria-checked', b.getAttribute('data-theme-value') === value ? 'true' : 'false');
    });
  }

  function hostOf(url) {
    try { return new URL(url).host; } catch (e) { return url; }
  }

  /** Обновить карточку подключения в сайдбаре. report — отчёт /api/connect или null. */
  function setConnection(report) {
    var box = document.getElementById('conn-status');
    if (!box) return;
    var title = document.getElementById('conn-status-text');
    var sub = document.getElementById('conn-status-sub');
    if (report) {
      box.setAttribute('data-state', 'on');
      title.textContent = report.user || 'Подключено';
      sub.textContent = hostOf(report.server);
      box.title = 'Подключено: ' + (report.user || 'пользователь n/a') + ' @ ' + report.server;
    } else {
      box.setAttribute('data-state', 'off');
      title.textContent = 'Не подключено';
      sub.textContent = 'кластер не выбран';
      box.title = '';
    }
  }

  function init() {
    applyTheme(stored());
    Array.prototype.forEach.call(document.querySelectorAll('[data-theme-value]'), function (b) {
      b.addEventListener('click', function () { applyTheme(b.getAttribute('data-theme-value')); });
    });
    // страница подключения сама запрашивает сессию; остальным — показать статус
    if (document.body.getAttribute('data-page') !== 'connect') {
      fetch('api/session', { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { setConnection(d && d.connected ? d.report : null); })
        .catch(function () { setConnection(null); });
    }
  }

  window.netinspectShell = { setConnection: setConnection };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
