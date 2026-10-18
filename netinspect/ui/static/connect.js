/* netinspect UI: подключение к кластеру по токену.
 * Токен отправляется только бэкенду (POST /api/connect) и в браузере не сохраняется.
 */
(function () {
  'use strict';

  var API = 'api/';
  var form, fields, resultBody, connectBtn, disconnectBtn, statusEl, statusText, parseResult;

  // ---------- утилиты ----------
  function $(id) { return document.getElementById(id); }
  function h(tag, cls, text, parent) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function api(method, path, body) {
    var opts = {
      method: method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Accept': 'application/json' }
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-Netinspect'] = '1';
      opts.body = JSON.stringify(body);
    }
    return fetch(API + path, opts).then(function (r) {
      return r.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!data) {
          // nginx отдал свою страницу: бэкенд не запущен (502) или нет location /api/
          var err = new Error(r.status === 502 || r.status === 504
            ? 'бэкенд netinspect не отвечает (HTTP ' + r.status + ')'
            : 'неожиданный ответ сервера (HTTP ' + r.status + ')');
          err.kind = 'backend';
          throw err;
        }
        return data;
      });
    }, function () {
      var err = new Error('нет связи с сервером netinspect');
      err.kind = 'backend';
      throw err;
    });
  }

  // ---------- разбор строки подключения ----------
  function unquote(s) { return s.replace(/^['"]|['"]$/g, ''); }

  /** Разобрать `oc login --token=... --server=...`, `oc login URL --token ...`, голый токен или URL. */
  function parseLogin(text) {
    var res = {};
    var t = text.trim();
    if (!t) return res;
    var m = t.match(/--token(?:=|\s+)(\S+)/);
    if (m) res.token = unquote(m[1]);
    m = t.match(/--server(?:=|\s+)(\S+)/);
    if (m) res.server = unquote(m[1]);
    if (!res.server) {
      m = t.match(/\blogin\s+(['"]?https?:\/\/\S+)/);
      if (m) res.server = unquote(m[1]);
    }
    if (/--insecure-skip-tls-verify(?:=true)?(?:\s|$)/.test(t)) res.insecure = true;
    if (!res.token && !res.server) {
      if (/^['"]?https?:\/\/\S+$/.test(t)) res.server = unquote(t);
      else if (/^(Bearer\s+)?\S+$/.test(t)) res.token = t.replace(/^Bearer\s+/, '');
    }
    return res;
  }

  function onLoginInput() {
    var parsed = parseLogin(fields.login.value);
    var found = [];
    if (parsed.server) { fields.server.value = parsed.server; found.push('адрес API'); }
    if (parsed.token) { fields.token.value = parsed.token; found.push('токен'); }
    if (parsed.insecure) { fields.insecure.checked = true; syncInsecure(); found.push('без проверки TLS'); }
    if (!fields.login.value.trim()) { parseResult.hidden = true; return; }
    parseResult.hidden = false;
    parseResult.className = 'parse-result ' + (found.length ? 'ok' : 'bad');
    parseResult.textContent = found.length
      ? 'Распознано: ' + found.join(', ')
      : 'Не удалось распознать. Ожидается: oc login --token=… --server=…';
  }

  function syncInsecure() {
    $('insecure-warn').hidden = !fields.insecure.checked;
    fields.ca.disabled = fields.insecure.checked;
    fields.caFile.disabled = fields.insecure.checked;
  }

  // ---------- состояние подключения ----------
  function setStatus(report) {
    if (report) {
      statusEl.className = 'conn-status on';
      statusText.textContent = 'Подключено: ' + (report.user || 'пользователь n/a') + ' @ ' + report.server;
      disconnectBtn.hidden = false;
    } else {
      statusEl.className = 'conn-status';
      statusText.textContent = 'Не подключено';
      disconnectBtn.hidden = true;
    }
  }

  function setBusy(busy) {
    connectBtn.disabled = busy;
    connectBtn.textContent = busy ? 'Проверяем…' : 'Проверить подключение';
    form.setAttribute('aria-busy', busy ? 'true' : 'false');
  }

  // ---------- вывод результата ----------
  var ERROR_TITLES = {
    auth: 'Токен не принят',
    tls: 'Ошибка TLS-сертификата',
    network: 'Кластер недоступен',
    forbidden: 'Недостаточно прав',
    input: 'Проверьте введённые данные',
    backend: 'Сервер netinspect недоступен',
    csrf: 'Запрос отклонён',
    internal: 'Внутренняя ошибка'
  };
  var ERROR_HINTS = {
    auth: ['Токен истёк или скопирован не полностью.', 'Получите новый: oc whoami -t или «Copy login command» в консоли.'],
    tls: ['Вставьте CA-сертификат кластера в разделе «TLS-сертификат кластера».',
          'Получить: oc get configmap kube-root-ca.crt -n default -o jsonpath=\'{.data.ca\\.crt}\''],
    network: ['Проверьте адрес API (обычно https://api.<кластер>:6443).',
              'Сервер netinspect должен иметь сетевой доступ к API кластера (прокси, firewall).'],
    backend: ['Запустите бэкенд: python -m netinspect serve', 'Проверьте, что nginx проксирует /api/ на 127.0.0.1:8081.']
  };

  function showLoading() {
    clear(resultBody);
    var p = h('p', 'loading', null, resultBody);
    h('span', 'spinner', null, p).setAttribute('aria-hidden', 'true');
    h('span', '', 'Проверяем подключение: версия кластера, пользователь, ресурсы Istio, права…', p);
  }

  function showError(kind, message) {
    clear(resultBody);
    var box = h('div', 'alert bad', null, resultBody);
    h('strong', '', '⚠ ' + (ERROR_TITLES[kind] || 'Ошибка'), box);
    h('p', '', message, box);
    var hints = ERROR_HINTS[kind];
    if (hints) {
      var ul = h('ul', 'hints', null, resultBody);
      hints.forEach(function (t) { h('li', '', t, ul); });
    }
  }

  function infoRow(dl, label, value) {
    h('dt', '', label, dl);
    var dd = h('dd', '', null, dl);
    if (typeof value === 'string') dd.textContent = value; else dd.appendChild(value);
  }

  function resourceTable(parent, title, rows) {
    if (!rows.length) return;
    var allowed = rows.filter(function (r) { return r.canList; }).length;
    var head = h('div', 'table-head', null, parent);
    h('h3', '', title, head);
    h('span', allowed === rows.length ? 'chip ok' : 'chip bad', 'читать можно: ' + allowed + ' из ' + rows.length, head);
    var wrap = h('div', 'table-wrap', null, parent);
    var table = h('table', 'res-table', null, wrap);
    var tr = h('tr', '', null, h('thead', '', null, table));
    ['Kind', 'API', 'Область', 'Чтение (list)'].forEach(function (t) { h('th', '', t, tr); });
    var tbody = h('tbody', '', null, table);
    rows.forEach(function (r) {
      var row = h('tr', '', null, tbody);
      h('td', 'kind', r.kind, row);
      h('td', 'mono', (r.group ? r.group + '/' : '') + r.version, row);
      h('td', '', r.namespaced ? 'namespace' : 'кластер', row);
      var cell = h('td', '', null, row);
      var mark = h('span', r.canList ? 'yes' : 'no', r.canList ? '✓ да' : '✗ нет', cell);
      if (!r.canList && r.reason) mark.title = r.reason;
    });
  }

  function showReport(data) {
    var rep = data.report;
    clear(resultBody);
    var box = h('div', 'alert ok', null, resultBody);
    h('strong', '', '✓ Подключение установлено', box);
    if (data.connectedAt) h('p', '', 'Сессия открыта: ' + data.connectedAt, box);

    var dl = h('dl', 'info', null, resultBody);
    infoRow(dl, 'Сервер', rep.server);
    infoRow(dl, 'Версия', rep.version);
    infoRow(dl, 'Пользователь', rep.user || 'n/a (не OpenShift)');
    infoRow(dl, 'OpenShift', rep.openshift ? 'да' : 'нет');
    infoRow(dl, 'Права проверены', rep.namespace ? 'в namespace ' + rep.namespace : 'на уровне кластера');
    var chips = h('span', 'chips');
    if (rep.istioGroups.length) rep.istioGroups.forEach(function (g) { h('span', 'chip', g, chips); });
    else h('span', 'chip bad', 'не найден', chips);
    infoRow(dl, 'Istio API', chips);

    if (rep.warnings && rep.warnings.length) {
      var w = h('div', 'alert warn', null, resultBody);
      h('strong', '', 'Предупреждения', w);
      var ul = h('ul', '', null, w);
      rep.warnings.forEach(function (t) { h('li', '', t, ul); });
    }
    resourceTable(resultBody, 'Ресурсы Istio', rep.resources.filter(function (r) { return r.istio; }));
    resourceTable(resultBody, 'Сетевые ресурсы Kubernetes / OpenShift', rep.resources.filter(function (r) { return !r.istio; }));
  }

  // ---------- действия ----------
  function onSubmit(ev) {
    ev.preventDefault();
    var body = {
      server: fields.server.value.trim(),
      token: fields.token.value.trim(),
      namespace: fields.namespace.value.trim(),
      insecure: fields.insecure.checked,
      caCert: fields.insecure.checked ? '' : fields.ca.value.trim()
    };
    if (!body.server || !body.token) {
      showError('input', !body.server ? 'Укажите адрес API кластера.' : 'Укажите токен.');
      (body.server ? fields.token : fields.server).focus();
      return;
    }
    setBusy(true);
    showLoading();
    api('POST', 'connect', body).then(function (data) {
      if (!data.ok) {
        showError(data.kind, data.error);
        if (data.kind === 'auth') fields.token.focus();
        return;
      }
      // токен больше не нужен в браузере — он хранится в сессии на сервере
      fields.token.value = '';
      fields.login.value = '';
      parseResult.hidden = true;
      setStatus(data.report);
      showReport(data);
    }, function (err) {
      showError(err.kind || 'backend', err.message);
    }).then(function () { setBusy(false); });
  }

  function onDisconnect() {
    api('POST', 'disconnect', {}).then(function () {
      setStatus(null);
      clear(resultBody);
      h('p', 'empty', 'Сессия закрыта. Токен удалён с сервера netinspect.', resultBody);
    }, function (err) { showError(err.kind || 'backend', err.message); });
  }

  function onCaFile() {
    var file = fields.caFile.files && fields.caFile.files[0];
    if (!file) return;
    if (file.size > 256 * 1024) { showError('input', 'Файл CA слишком большой.'); return; }
    var reader = new FileReader();
    reader.onload = function () { fields.ca.value = String(reader.result || ''); };
    reader.readAsText(file);
  }

  function init() {
    form = $('connect-form');
    fields = {
      login: $('login-cmd'), server: $('server'), token: $('token'), namespace: $('namespace'),
      ca: $('ca-cert'), caFile: $('ca-file'), insecure: $('insecure')
    };
    resultBody = $('result-body');
    connectBtn = $('connect-btn');
    disconnectBtn = $('disconnect-btn');
    statusEl = $('conn-status');
    statusText = $('conn-status-text');
    parseResult = $('parse-result');

    fields.login.addEventListener('input', onLoginInput);
    fields.insecure.addEventListener('change', syncInsecure);
    fields.caFile.addEventListener('change', onCaFile);
    form.addEventListener('submit', onSubmit);
    disconnectBtn.addEventListener('click', onDisconnect);
    $('toggle-token').addEventListener('click', function () {
      var show = fields.token.type === 'password';
      fields.token.type = show ? 'text' : 'password';
      this.textContent = show ? 'Скрыть' : 'Показать';
      this.setAttribute('aria-pressed', show ? 'true' : 'false');
    });

    // уже подключены? (сессия на сервере, cookie HttpOnly)
    api('GET', 'session').then(function (data) {
      if (data.ok && data.connected) { setStatus(data.report); showReport(data); }
    }, function (err) {
      showError('backend', err.message);
    });
  }

  // для тестов разбора строки подключения
  window.netinspectParseLogin = parseLogin;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
