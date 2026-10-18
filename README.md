# netinspect

Инструмент для диагностики сетевых правил OpenShift / Kubernetes с Istio.
Строит граф связей

```
Gateway → VirtualService → DestinationRule
                         → Service / внешний хост → EndpointSlice
Route (OpenShift) → Service
```

и показывает его в веб-интерфейсе. Битые ссылки
(несуществующий Gateway или Service, отсутствующий subset в DestinationRule,
Service без endpoints) подсвечиваются.

## Требования

- **Python 3.10+, только стандартная библиотека.** Никаких `pip install` не нужно.
- **PyYAML — опционально.** Если он установлен, манифесты показываются в YAML,
  читаются `.yaml`/`.yml` файлы и доступен `get -o yaml`. Без него всё работает
  на JSON, YAML-файлы в каталоге пропускаются с предупреждением.
- **nginx** — не обязателен. Нужен только для установки на сервер с HTTPS; локально интерфейс раздаёт сам `serve`.

Запуск без установки, из корня репозитория:

```bash
python -m netinspect --help
```

## Быстрый старт: веб-интерфейс

Приложение запускается **без токена** — адрес кластера и токен вводятся в браузере.

```bash
python -m netinspect serve
```

nginx не нужен: `serve` сам раздаёт интерфейс и API. Слушает только
127.0.0.1:8081, то есть доступен лишь с этой машины.

Откройте http://127.0.0.1:8081/ и вставьте строку подключения. Её даёт консоль
OpenShift: меню пользователя → «Copy login command». Подходит строка вида
`oc login --token=sha256~… --server=https://api.<кластер>:6443`. Поля «Адрес API» и
«Токен» заполнятся сами; их можно ввести и вручную. Нажмите «Проверить подключение».

Приложение покажет:

- версию кластера, пользователя и признак OpenShift;
- найденные API Istio;
- права на чтение (`list`) для каждого ресурса Istio и для Service / EndpointSlice / Route.

Список ресурсов Istio не зашит в код. Это всё, что кластер отдаёт в группах
`*.istio.io`: VirtualService, Gateway, DestinationRule, ServiceEntry, Sidecar,
EnvoyFilter, WorkloadEntry, AuthorizationPolicy, PeerAuthentication,
RequestAuthentication, Telemetry и т.д.

Подключение идёт только по токену: в интерфейсе нет настроек сертификата и
namespace, права проверяются на уровне всего кластера. Сертификат API кластера
проверяется по доверенным CA системы. Если появилась ошибка TLS, см. раздел
«TLS-сертификат кластера» ниже.

**Куда уходит токен.** Браузер отправляет токен один раз, в `POST /api/connect`.
Бэкенд держит его в памяти на время сессии: по умолчанию 8 часов бездействия,
настраивается через `serve --session-ttl`. Браузер получает только случайный
идентификатор сессии в `HttpOnly`-cookie. В браузере токен не сохраняется
(ни localStorage, ни cookie). В ответы API и логи он не попадает. Кнопка
«Отключиться» удаляет сессию на сервере. Перезапуск `serve` удаляет все сессии.

> Вне `localhost` открывайте интерфейс только по HTTPS (заготовка в
> `deploy/nginx/netinspect.conf`): иначе токен пойдёт по сети открытым текстом.

## Дизайн интерфейса

- **Палитра.** Нейтральная холодная шкала «slate» и один акцент «iris»
  (индиго-фиолетовый). Подход взят у Linear и Radix Colors: у каждого токена своя
  роль (фон, поверхность, состояние, рамка, текст).
- **Цвета типов узлов** — соседние оттенки одного сектора цветового круга (cyan,
  sky, iris, violet, teal), поэтому они гармонируют между собой. Красный и янтарный
  оставлены только для проблем, как в Kiali.
- **Темы:** светлая и тёмная. По умолчанию тема следует системной; переключатель
  находится внизу сайдбара, выбор хранится только в браузере.
- **Контраст** текста в обеих темах — не ниже WCAG AA (4.5:1). Это проверяет тест
  `tests/test_theme.py`.
- **Шрифты:** Inter для интерфейса и JetBrains Mono для данных (хосты, версии, YAML).
  Эту пару использует, например, GitLab. Файлы шрифтов (латиница и кириллица,
  около 120 КБ) лежат в `netinspect/ui/static/fonts` под лицензией SIL OFL 1.1,
  поэтому интерфейс не обращается в интернет.
- **Источник токенов** — `netinspect/ui/theme.py`. После правки палитры обновите
  `theme.css`:
  `python -c "from netinspect.graph.render_web import theme_css; open('netinspect/ui/static/theme.css','w').write(theme_css())"`.

## Подключение к кластеру из командной строки

Нужны адрес API и личный токен.

**Токен.** Получите его после `oc login`:

```bash
export NETINSPECT_TOKEN=$(oc whoami -t)
```

Токен **не передаётся аргументом** командной строки, чтобы не попасть в историю
shell. Порядок поиска:

1. `--token-env ИМЯ` — имя переменной окружения с токеном;
2. переменная `NETINSPECT_TOKEN`;
3. интерактивный ввод (`getpass`, без эха).

Токен не пишется в логи, `repr`, тексты ошибок и веб-интерфейс; в отладочном логе
видна только маска `****` + последние 4 символа.

**Адрес API:** `--server https://api.cluster.example:6443` или `NETINSPECT_SERVER`
(узнать: `oc whoami --show-server`).

### TLS-сертификат кластера

Сертификат API кластера всегда проверяется: и в веб-интерфейсе, и в командной
строке. Проверка идёт по доверенным CA операционной системы — так же, как у `oc`
и браузера. Отключить проверку нельзя, указывать CA вручную не нужно.

Если появилась «Ошибка TLS-сертификата», значит CA кластера не доверен на машине,
где запущен netinspect. Его добавляют в систему один раз:

```bash
# получить CA кластера (после oc login)
oc config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > cluster-ca.crt

# RHEL / CentOS / Fedora
sudo cp cluster-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
# Debian / Ubuntu
sudo cp cluster-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
```

Без прав root можно собрать свой бандл и указать его через стандартную
переменную OpenSSL `SSL_CERT_FILE`:

```bash
cat /etc/ssl/certs/ca-certificates.crt cluster-ca.crt > ~/netinspect-ca.pem   # путь к системному бандлу зависит от ОС
SSL_CERT_FILE=~/netinspect-ca.pem python -m netinspect serve
```

Прочее: `--timeout` (по умолчанию 15 с), `--proxy URL`. Без `--proxy` действуют
стандартные `HTTPS_PROXY` / `NO_PROXY`.

## Команды

### connect — проверка подключения

```bash
python -m netinspect connect --server https://api.cluster.example:6443 -n prod
```

Выводит версию кластера (`/version`), пользователя (`user.openshift.io/users/~`,
для «чистого» Kubernetes — `n/a`), найденные версии Istio API, признак OpenShift
и таблицу прав на `list` (через `SelfSubjectAccessReview`). В таблицу попадают
все ресурсы Istio, найденные в кластере, плюс Service, EndpointSlice и Route.
То же самое показывает веб-интерфейс.

### get — список ресурсов одного типа

```bash
python -m netinspect get vs -n prod
python -m netinspect get vs -A -o json
python -m netinspect get dr --from-dir ./manifests -o yaml
```

Типы: `gw`, `vs`, `dr`, `svc`, `endpointslice` (`eps`), `route` или полные имена.
Для VirtualService колонки: namespace, name, hosts, gateways, destinations (FQDN).
Без `-n` берутся все namespace.

### graph — граф связей

```bash
# весь граф по namespace
python -m netinspect graph -n prod -n staging

# от хоста: все Gateway, VirtualService и Route, у которых совпадает хост (с учётом wildcard)
python -m netinspect graph -A --host api.example.com

# от конкретного ресурса
python -m netinspect graph -A --resource vs/prod/reviews
```

Граф в консоль не выводится. Команда строит его и выгружает в каталог (по
умолчанию `web/`), а смотреть его нужно в веб-интерфейсе, на странице «Граф».
В консоли печатается только итог:

```
Граф выгружен в web: узлов 20, связей 20, с проблемами 4. Смотреть: python -m netinspect serve --graph-dir web → http://127.0.0.1:8081/graph.html
```

Опции:

| Опция | Назначение |
|---|---|
| `--host H` / `--resource KIND/NS/NAME` | точка входа; без неё — весь граф |
| `-n NS` (несколько раз) / `-A` | namespace |
| `--from-dir DIR` | читать манифесты из каталога вместо кластера |
| `--web-dir DIR` | куда выгрузить граф (по умолчанию `web`) |
| `--cluster-domain D` | домен кластера, по умолчанию `cluster.local` |
| `-v` / `-vv` | подробный / отладочный лог |

Подграф от точки входа строится обходом в ширину отдельно вниз (по трафику) и
вверх (против трафика). Gateway, совпавший с `--host` по wildcard, добавляется в
граф, но не разворачивается — иначе в отчёт попали бы все VirtualService этого
Gateway.

**Коды выхода:** `0` — успешно, проблем нет; `1` — ошибка (подключение, права,
аргументы); `2` — граф построен, но найдены проблемы (удобно для CI).

### Веб-интерфейс и nginx

Без nginx достаточно `python -m netinspect serve`, адрес http://127.0.0.1:8081/
(см. «Быстрый старт»). Страница «Граф» берёт `graph.json` из каталога `web/`;
другой каталог задаётся через `serve --graph-dir DIR`.

С nginx (сервер, HTTPS, общий доступ) бэкенд запускают как
`python -m netinspect serve --api-only`. Статику тогда раздаёт nginx, а `/api/`
он проксирует на бэкенд.

Состав:

| Часть | Где | Что делает |
|---|---|---|
| статика | `netinspect/ui/static/` | `index.html` + `connect.js` — подключение к кластеру; `graph.html` + `app.js` — граф; `style.css`, `theme.css` |
| бэкенд | `python -m netinspect serve` | интерфейс и JSON API на 127.0.0.1:8081: `/api/connect`, `/api/session`, `/api/disconnect`, `/api/health` (с `--api-only` — только API) |
| nginx | `deploy/nginx/` | раздаёт статику и проксирует `/api/` на бэкенд |

Браузер не может обращаться к API кластера напрямую: мешают CORS и CA кластера.
Поэтому запросы к кластеру делает бэкенд.

`theme.css` генерируется из `netinspect/ui/theme.py`, а в репозитории лежит его
актуальная копия. Если поменяли палитру, обновите файл; тест
`test_committed_theme_css_is_current` напомнит об этом.

Граф пока строится командой `graph --web-dir DIR`. Она выгружает статику и
`graph.json`; страница «Граф» читает `graph.json`. В локальном конфиге nginx
`graph.json` берётся из `web/`:

```bash
python -m netinspect graph -A --web-dir web
```

**Системный nginx** (`deploy/nginx/netinspect.conf`, порт 8080, root `/var/www/netinspect`):

```bash
sudo cp deploy/nginx/netinspect.conf deploy/nginx/netinspect-common.inc /etc/nginx/conf.d/
sudo mkdir -p /var/www/netinspect && sudo cp netinspect/ui/static/* /var/www/netinspect/
python -m netinspect serve --api-only      # лучше как systemd-сервис
sudo nginx -t && sudo nginx -s reload
```

**nginx без root** (`deploy/nginx/nginx-local.conf`, 127.0.0.1:8080):

```bash
python -m netinspect serve --api-only
nginx -p "$PWD" -e stderr -c deploy/nginx/nginx-local.conf
```

Общие правила вынесены в `deploy/nginx/netinspect-common.inc`:

- строгий `Content-Security-Policy` (`script-src 'self'`, `style-src 'self'`): в
  разметке нет inline-скриптов, стилей и обработчиков;
- `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`;
- статика — только `GET`/`HEAD`, скрытые файлы закрыты, `Cache-Control: no-cache`;
- `/api/` проксируется на `127.0.0.1:8081`, тело запроса ограничено 512 КБ;
- gzip для JSON, CSS и JS.

Бэкенд принимает POST только с `Content-Type: application/json` и заголовком
`X-Netinspect: 1` (защита от CSRF); cookie сессии — `HttpOnly; SameSite=Strict`.

> `graph.json` содержит манифесты ресурсов кластера (Secret не загружаются).
> Публикуйте интерфейс только во внутренней сети или включите `auth_basic` —
> заготовка есть в `netinspect.conf`.

Возможности страницы «Граф»:

- колонки по направлению трафика: Gateway/Route → VirtualService → DestinationRule → Service/External → EndpointSlice;
- клик по узлу — панель с бейджами, проблемами, связанными узлами (кликабельны) и
  манифестом (YAML с PyYAML, иначе JSON) с кнопкой «Копировать»;
- поиск по имени или хосту (`/` — фокус в поле поиска), фильтр по namespace, чекбоксы по типам;
- зум колесом, перетаскивание холста, кнопка «Вписать»;
- в шапке — источник, время, число узлов и проблем, список проблем и предупреждений загрузки.

Secret-ресурсы не загружаются никогда; из манифестов удаляются `managedFields` и
аннотация `kubectl.kubernetes.io/last-applied-configuration`.

## Работа без кластера (на фикстурах)

```bash
python -m netinspect graph --from-dir tests/fixtures -A --web-dir web   # код выхода 2
nginx -p "$PWD" -e stderr -c deploy/nginx/nginx-local.conf      # http://127.0.0.1:8080/
python -m netinspect get vs --from-dir tests/fixtures
```

`--from-dir` читает `.json` (и `.yaml`/`.yml` при наличии PyYAML) рекурсивно;
поддерживаются одиночные объекты, `kind: List` и многодокументный YAML. Удобно
для разбора выгрузки `oc get vs,dr,gw,svc,endpointslices,routes -A -o json > dump.json`.

Фикстуры покрывают: рабочую цепочку GW → VS → DR(v1, v2) → Service → EndpointSlice,
VS со ссылкой на несуществующий Gateway, несуществующий subset, Service без
endpoints, короткий и полный хост в разных namespace, wildcard-хост на Gateway,
OpenShift Route → Service (в т.ч. несуществующий alternateBackend) и внешний хост.

## Необходимые права RBAC

Только чтение: `list` на

| Ресурс | API группа |
|---|---|
| gateways, virtualservices, destinationrules | networking.istio.io |
| services | "" (core) |
| endpointslices | discovery.k8s.io |
| routes (OpenShift) | route.openshift.io |

Плюс чтение discovery API (`/apis`, `/api/v1` — роль `system:discovery`, есть у всех
аутентифицированных) и `create` на `selfsubjectaccessreviews` (есть у всех аутентифицированных
пользователей по умолчанию). Типы без прав не прерывают загрузку — они
перечисляются в предупреждениях.

## Как правильно читаются хосты

- `reviews` в VS/DR namespace `prod` → `reviews.prod.svc.cluster.local`;
- `reviews.prod` → `reviews.prod.svc.cluster.local`, `reviews.prod.svc` → то же;
- полный FQDN и внешние хосты (`api.example.com`) не меняются; регистр и завершающая точка нормализуются;
- `*` совпадает с любым хостом; `*.example.com` — с `a.example.com` и `a.b.example.com`, но не с `example.com`;
- хосты Gateway в формате `ns/host` учитываются;
- хост назначения вне `*.svc.<domain>` показывается узлом `ExternalHost`, а не битой ссылкой.

## Разработка

```bash
python -m unittest discover -s tests
```

Тесты не ходят во внешнюю сеть. `ApiClient` проверяется подменой opener, граф
строится через `DirectorySource` на фикстурах, а бэкенд — против
`tests/fake_cluster.py`, локального HTTP-сервера на 127.0.0.1.

Ручная проверка интерфейса без кластера:

```bash
python -m tests.fake_cluster 18443   # печатает адрес и тестовый токен
python -m netinspect serve           # http://127.0.0.1:8081/
# в интерфейсе: oc login --token=sha256~good-token-0001 --server=http://127.0.0.1:18443
```

Структура:

```
netinspect/
  core/   — подключение (config, client, errors), discovery, access, реестр типов,
            fetcher (ClusterSource / DirectorySource), модели, хосты
  graph/  — builder (связи), traverse (подграфы), render_web (выгрузка графа для UI)
  server/ — бэкенд веб-интерфейса: app.py (JSON API), sessions.py (сессии в памяти)
  ui/     — theme.py: палитра, единый источник цветов интерфейса;
            static/: index.html + connect.js, graph.html + app.js, shell.js, theme-init.js,
            style.css, theme.css, fonts/ (Inter, JetBrains Mono — OFL 1.1)
deploy/nginx/ — конфигурация nginx для веб-интерфейса
tests/fake_cluster.py — фейковый API кластера с Istio для тестов и ручной проверки
```

`core` и `graph` не зависят от CLI и веб-интерфейса. Новый тип ресурса добавляется одной
записью в `core/resources.py` (`REGISTRY`) и методом-линкером в `graph/builder.py`.

## Ограничения текущей версии

- Учитываются `route[].destination` в `http`/`tcp`/`tls`; `mirror`, `delegate`,
  `match[].gateways`, `exportTo` и `ServiceEntry` пока не анализируются
  (хост вне кластера показывается как ExternalHost).
- Сопоставление VS ↔ Gateway идёт по `spec.gateways`; пересечение хостов VS и
  серверов Gateway не проверяется.
- DestinationRule ищется по точному FQDN, затем по wildcard; правила видимости
  (`exportTo`, namespace корня mesh) не учитываются.
- Нет kubeconfig: подключение только по токену.

## Дальше

1. **Граф в веб-интерфейсе по текущей сессии** — без `graph --web-dir`, с учётом всех
   найденных ресурсов Istio (ServiceEntry, Sidecar, AuthorizationPolicy и др.).
2. **Проверка дублей и конфликтов:** несколько VS на один хост и Gateway,
   несколько DR на один host, пересекающиеся Route. Граф и `hosts.py` уже дают
   всё нужное — проверки лягут отдельным модулем поверх `Graph`.
3. **Каталог диагностических команд:** для узла с проблемой — готовые команды
   `oc`/`istioctl` (`istioctl x describe`, `proxy-config routes`, `oc get endpointslices -l ...`)
   в панели веб-интерфейса.
4. Учёт `exportTo`, `delegate` в связях графа.
