/* netinspect UI: подключение к кластеру по токену.
 * Токен отправляется только бэкенду (POST /api/connect) и в браузере не сохраняется.
 */
(function () {
  'use strict';

  var API = 'api/';
  var SVGNS = 'http://www.w3.org/2000/svg';
  var form, fields, resultBody, connectBtn, disconnectBtn, parseResult;
  var tableState = { filter: 'all', query: '', onlyDenied: false };
  var lastReport = null;

  // ---------- утилиты ----------
  function $(id) { return document.getElementById(id); }
  function h(tag, cls, text, parent) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function icon(name, cls, parent) {
    var svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('class', cls || 'icon');
    svg.setAttribute('aria-hidden', 'true');
    var use = document.createElementNS(SVGNS, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    if (parent) parent.appendChild(svg);
    return svg;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function hostOf(url) { try { return new URL(url).host; } catch (e) { return url; } }
  function shell() { return window.netinspectShell || { setConnection: function () {} }; }

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

  // ---------- типы ресурсов: метка и цвет ----------
  var KIND_TOKENS = {
    Gateway: 'gateway', Route: 'route', VirtualService: 'vs', DestinationRule: 'dr',
    Service: 'svc', EndpointSlice: 'eps'
  };
  var GROUP_TOKENS = {
    'networking.istio.io': 'vs', 'security.istio.io': 'dr', 'telemetry.istio.io': 'gateway',
    'extensions.istio.io': 'gateway', 'route.openshift.io': 'route', 'discovery.k8s.io': 'eps', '': 'svc'
  };
  var KIND_ABBR = { Service: 'SVC', EndpointSlice: 'EPS', Route: 'RT', Gateway: 'GW' };

  function abbr(kind) {
    if (KIND_ABBR[kind]) return KIND_ABBR[kind];
    var caps = kind.replace(/[^A-Z]/g, '');
    return (caps.length >= 2 ? caps : kind.slice(0, 2)).slice(0, 3).toUpperCase();
  }
  function kindTag(res, parent) {
    var tok = KIND_TOKENS[res.kind] || GROUP_TOKENS[res.group] || 'eps';
    var t = h('span', 'kind-tag', abbr(res.kind), parent);
    t.style.color = 'var(--kind-' + tok + ')';
    t.style.background = 'var(--kind-' + tok + '-soft)';
    t.setAttribute('aria-hidden', 'true');
    return t;
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
    if (parsed.insecure) { fields.insecure.checked = true; $('advanced').open = true; syncInsecure(); found.push('без проверки TLS'); }
    clear(parseResult);
    if (!fields.login.value.trim()) { parseResult.hidden = true; return; }
    parseResult.hidden = false;
    if (found.length) {
      found.forEach(function (f) {
        var b = h('span', 'badge badge-success', null, parseResult);
        icon('check-circle', 'icon', b);
        h('span', '', f, b);
      });
    } else {
      var b = h('span', 'badge badge-danger', null, parseResult);
      icon('alert-circle', 'icon', b);
      h('span', '', 'не распознано — нужна строка oc login --token=… --server=…', b);
    }
  }

  function syncInsecure() {
    $('insecure-warn').hidden = !fields.insecure.checked;
    fields.ca.disabled = fields.insecure.checked;
    fields.caFile.disabled = fields.insecure.checked;
  }

  function setConnected(report) {
    lastReport = report;
    disconnectBtn.hidden = !report;
    shell().setConnection(report);
  }

  function setBusy(busy) {
    connectBtn.disabled = busy;
    connectBtn.setAttribute('aria-busy', busy ? 'true' : 'false');
    connectBtn.querySelector('.btn-label').textContent = busy ? 'Проверяем…' : 'Проверить подключение';
    form.setAttribute('aria-busy', busy ? 'true' : 'false');
  }

  // ---------- состояния панели результата ----------
  function card(cls) { return h('div', 'card ' + (cls || ''), null, resultBody); }

  function showEmpty(note) {
    clear(resultBody);
    var c = card('empty-state');
    var art = document.createElementNS(SVGNS, 'svg');
    art.setAttribute('class', 'empty-art');
    art.setAttribute('viewBox', '0 0 180 120');
    art.setAttribute('aria-hidden', 'true');
    [['M44 60 L90 30', 'e'], ['M44 60 L90 90', 'e'], ['M90 30 L136 60', 'e'], ['M90 90 L136 60', 'e']].forEach(function (p) {
      var path = document.createElementNS(SVGNS, 'path');
      path.setAttribute('d', p[0]); path.setAttribute('class', p[1]); art.appendChild(path);
    });
    [[44, 60, 'n n1'], [90, 30, 'n n2'], [90, 90, 'n n2'], [136, 60, 'n n3']].forEach(function (p) {
      var r = document.createElementNS(SVGNS, 'rect');
      r.setAttribute('x', p[0] - 16); r.setAttribute('y', p[1] - 12);
      r.setAttribute('width', 32); r.setAttribute('height', 24); r.setAttribute('rx', 7);
      r.setAttribute('class', p[2]); art.appendChild(r);
    });
    c.appendChild(art);
    h('h2', '', note ? 'Сессия закрыта' : 'Подключитесь к кластеру', c);
    h('p', '', note || 'netinspect покажет версию кластера, найденные API Istio и права на чтение каждого ресурса.', c);
    var ol = h('ol', 'steps', null, c);
    var s1 = h('li', null, null, ol); h('span', '', null, s1).append('Откройте консоль OpenShift → ваше имя → ', bold('Copy login command'), '.');
    var s2 = h('li', null, null, ol); h('span', '', null, s2).append('Вставьте строку ', bold('oc login …'), ' в поле слева — адрес и токен распознаются сами.');
    var s3 = h('li', null, null, ol); h('span', '', null, s3).append('Нажмите ', bold('Проверить подключение'), '.');
  }
  function bold(t) { var b = document.createElement('b'); b.textContent = t; return b; }

  function showLoading() {
    clear(resultBody);
    var c = card('card-pad');
    h('div', 'card-title', 'Проверяем подключение…', c);
    var bar = h('div', 'progress indeterminate', null, c); h('span', '', null, bar);
    bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-label', 'Проверка подключения');
    var ul = h('ul', 'checklist', null, c);
    ['Доступность API и токен', 'Пользователь и тип кластера', 'Ресурсы Istio в кластере', 'Права на чтение ресурсов'].forEach(function (t) {
      var li = h('li', '', null, ul);
      h('span', 'spinner', null, li).setAttribute('aria-hidden', 'true');
      h('span', '', t, li);
    });
    var stats = h('div', 'stats', null, resultBody);
    for (var i = 0; i < 4; i++) { var s = h('div', 'card stat', null, stats); h('div', 'skeleton sk-line', null, s); h('div', 'skeleton sk-big', null, s); }
  }

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
    auth: [['Токен истёк или скопирован не полностью.'], ['Получите новый: ', 'oc whoami -t', ' или «Copy login command» в консоли.']],
    tls: [['Откройте «Дополнительно» и вставьте CA-сертификат кластера.'],
          ['Получить CA: ', 'oc get configmap kube-root-ca.crt -n default -o jsonpath=\'{.data.ca\\.crt}\'']],
    network: [['Проверьте адрес API — обычно ', 'https://api.<кластер>:6443', '.'],
              ['Сервер netinspect должен видеть API кластера: прокси, firewall, VPN.']],
    backend: [['Запустите: ', 'python -m netinspect serve'],
              ['Если интерфейс открыт через nginx — проверьте, что он проксирует /api/ на 127.0.0.1:8081.']]
  };

  function showError(kind, message) {
    clear(resultBody);
    var box = h('div', 'callout callout-danger', null, resultBody);
    box.setAttribute('role', 'alert');
    icon('alert-circle', 'icon icon-lg', box);
    var body = h('div', 'callout-body', null, box);
    h('div', 'callout-title', ERROR_TITLES[kind] || 'Ошибка', body);
    h('div', 'callout-text', message, body);
    var hints = ERROR_HINTS[kind];
    if (hints) {
      var c = card('card-pad');
      h('div', 'card-title', 'Что проверить', c);
      var ul = h('ul', 'hint-list', null, c);
      hints.forEach(function (parts) {
        var li = h('li', '', null, ul);
        parts.forEach(function (p, i) {
          if (i % 2 === 1) h('code', 'inline', p, li); else li.append(p);
        });
      });
    }
  }

  function stat(parent, iconName, label, value, sub, mono) {
    var s = h('div', 'card stat', null, parent);
    var l = h('div', 'stat-label', null, s); icon(iconName, 'icon', l); h('span', '', label, l);
    var v = h('div', 'stat-value' + (mono ? ' mono' : ''), value, s);
    v.title = value;
    if (sub !== null && sub !== undefined) {
      if (typeof sub === 'string') h('div', 'stat-sub', sub, s); else s.appendChild(sub);
    }
    return s;
  }

  function showReport(data) {
    var rep = data.report;
    clear(resultBody);
    var ok = h('div', 'callout callout-success', null, resultBody);
    icon('check-circle', 'icon icon-lg', ok);
    var okb = h('div', 'callout-body', null, ok);
    h('div', 'callout-title', 'Подключено к ' + hostOf(rep.server), okb);
    h('div', 'callout-text', (rep.user ? 'Пользователь ' + rep.user : 'Пользователь не определён (не OpenShift)') +
      (data.connectedAt ? ' · сессия с ' + data.connectedAt : ''), okb);

    var istio = rep.resources.filter(function (r) { return r.istio; });
    var allowed = rep.resources.filter(function (r) { return r.canList; }).length;
    var total = rep.resources.length;

    var stats = h('div', 'stats', null, resultBody);
    stat(stats, 'server', 'Версия кластера', rep.version, rep.openshift ? 'OpenShift' : 'Kubernetes', true);
    stat(stats, 'user', 'Пользователь', rep.user || 'n/a', rep.namespace ? 'права в namespace ' + rep.namespace : 'права на уровне кластера');
    stat(stats, 'layers', 'Ресурсы Istio', String(istio.length),
      rep.istioGroups.length ? rep.istioGroups.length + ' ' + plural(rep.istioGroups.length, 'группа', 'группы', 'групп') + ' API' : 'Istio не найден');
    var accessSub = h('div', '', null);
    var bar = h('div', 'progress' + (allowed === total ? '' : ' warn'), null, accessSub);
    var fill = h('span', '', null, bar);
    fill.style.width = (total ? Math.round(allowed * 100 / total) : 0) + '%';
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuenow', String(allowed)); bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', String(total));
    bar.setAttribute('aria-label', 'Доступно для чтения');
    stat(stats, 'shield', 'Доступ на чтение', allowed + ' из ' + total, accessSub);

    if (rep.istioGroups.length) {
      var gc = h('div', 'chips', null, resultBody);
      rep.istioGroups.forEach(function (g) { h('span', 'badge badge-accent mono', g, gc); });
    }

    if (rep.warnings && rep.warnings.length) {
      var w = h('div', 'callout callout-warning', null, resultBody);
      icon('alert', 'icon', w);
      var wb = h('div', 'callout-body', null, w);
      h('div', 'callout-title', 'Предупреждения', wb);
      var ul = h('ul', '', null, wb);
      rep.warnings.forEach(function (t) { h('li', '', t, ul); });
    }

    var tc = card('');
    var head = h('div', 'card-head', null, tc);
    var titles = h('div', '', null, head);
    h('div', 'card-title', 'Ресурсы и права', titles);
    h('div', 'card-sub', 'Проверка list через SelfSubjectAccessReview', titles);
    var tools = h('div', 'table-tools', null, head);
    var seg = h('div', 'segmented', null, tools);
    seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', 'Фильтр ресурсов');
    [['all', 'Все', total], ['istio', 'Istio', istio.length], ['k8s', 'Kubernetes', total - istio.length]].forEach(function (f) {
      var b = h('button', '', null, seg);
      b.type = 'button';
      b.setAttribute('aria-pressed', tableState.filter === f[0] ? 'true' : 'false');
      h('span', '', f[1], b); h('span', 'count', String(f[2]), b);
      b.addEventListener('click', function () {
        tableState.filter = f[0];
        Array.prototype.forEach.call(seg.children, function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
        renderRows();
      });
    });
    var sw = h('div', 'input-wrap has-icon', null, tools);
    icon('search', 'icon', sw);
    var q = h('input', 'input', null, sw);
    q.type = 'search'; q.placeholder = 'Найти kind'; q.setAttribute('aria-label', 'Найти ресурс');
    q.value = tableState.query;
    q.addEventListener('input', function () { tableState.query = q.value.trim().toLowerCase(); renderRows(); });
    var chk = h('label', 'check', null, tools);
    var cb = h('input', '', null, chk); cb.type = 'checkbox'; cb.checked = tableState.onlyDenied;
    h('span', '', 'только без доступа', chk);
    cb.addEventListener('change', function () { tableState.onlyDenied = cb.checked; renderRows(); });

    var wrap = h('div', 'table-wrap', null, tc);
    var table = h('table', 'table', null, wrap);
    var tr = h('tr', '', null, h('thead', '', null, table));
    ['Ресурс', 'API', 'Область', 'Доступ'].forEach(function (t) { var th = h('th', '', t, tr); th.scope = 'col'; });
    var tbody = h('tbody', '', null, table);

    function renderRows() {
      clear(tbody);
      var rows = rep.resources.filter(function (r) {
        if (tableState.filter === 'istio' && !r.istio) return false;
        if (tableState.filter === 'k8s' && r.istio) return false;
        if (tableState.onlyDenied && r.canList) return false;
        if (tableState.query && (r.kind + ' ' + r.plural + ' ' + r.group).toLowerCase().indexOf(tableState.query) < 0) return false;
        return true;
      });
      if (!rows.length) {
        var td = h('td', 'table-empty', 'Ничего не найдено', h('tr', '', null, tbody));
        td.colSpan = 4;
        return;
      }
      rows.forEach(function (r) {
        var row = h('tr', '', null, tbody);
        var k = h('div', 'kind-cell', null, h('td', '', null, row));
        kindTag(r, k); h('span', '', r.kind, k);
        h('td', 'mono', (r.group ? r.group + '/' : '') + r.version, row);
        h('td', 'muted', r.namespaced ? 'namespace' : 'кластер', row);
        var cell = h('td', '', null, row);
        var b = h('span', r.canList ? 'badge badge-success' : 'badge badge-danger', null, cell);
        h('span', 'dot', null, b);
        h('span', '', r.canList ? 'чтение' : 'нет доступа', b);
        if (!r.canList && r.reason) b.title = r.reason;
      });
    }
    renderRows();
  }

  function plural(n, one, few, many) {
    var m10 = n % 10, m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
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
        if (data.kind === 'tls') $('advanced').open = true;
        return;
      }
      // токен больше не нужен в браузере — он хранится в сессии на сервере
      fields.token.value = '';
      fields.login.value = '';
      clear(parseResult);
      parseResult.hidden = true;
      setConnected(data.report);
      showReport(data);
    }, function (err) {
      showError(err.kind || 'backend', err.message);
    }).then(function () { setBusy(false); });
  }

  function onDisconnect() {
    api('POST', 'disconnect', {}).then(function () {
      setConnected(null);
      showEmpty('Токен удалён с сервера netinspect. Чтобы продолжить, подключитесь снова.');
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
    parseResult = $('parse-result');

    fields.login.addEventListener('input', onLoginInput);
    fields.insecure.addEventListener('change', syncInsecure);
    fields.caFile.addEventListener('change', onCaFile);
    form.addEventListener('submit', onSubmit);
    disconnectBtn.addEventListener('click', onDisconnect);
    var toggle = $('toggle-token');
    toggle.addEventListener('click', function () {
      var show = fields.token.type === 'password';
      fields.token.type = show ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
      toggle.setAttribute('aria-label', show ? 'Скрыть токен' : 'Показать токен');
      toggle.title = show ? 'Скрыть токен' : 'Показать токен';
      toggle.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
    });

    showEmpty();
    // уже подключены? (сессия на сервере, cookie HttpOnly)
    api('GET', 'session').then(function (data) {
      if (data.ok && data.connected) { setConnected(data.report); showReport(data); }
      else setConnected(null);
    }, function (err) {
      setConnected(null);
      showError('backend', err.message);
    });
  }

  // для тестов разбора строки подключения
  window.netinspectParseLogin = parseLogin;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
