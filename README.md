# netinspect

Инструмент для диагностики сетевых правил OpenShift / Kubernetes с Istio.
Строит граф связей

```
Gateway → VirtualService → DestinationRule
                         → Service / внешний хост → EndpointSlice
Route (OpenShift) → Service
```

и показывает его деревом в консоли и интерактивным HTML-отчётом. Битые ссылки
(несуществующий Gateway или Service, отсутствующий subset в DestinationRule,
Service без endpoints) подсвечиваются.

## Требования

- **Python 3.10+, только стандартная библиотека.** Никаких `pip install` не нужно.
- **PyYAML — опционально.** Если он установлен, манифесты показываются в YAML,
  читаются `.yaml`/`.yml` файлы и доступен `get -o yaml`. Без него всё работает
  на JSON, YAML-файлы в каталоге пропускаются с предупреждением.

Запуск без установки, из корня репозитория:

```bash
python -m netinspect --help
```

## Подключение к кластеру

Нужны адрес API, личный токен и (желательно) CA-сертификат API.

**Токен.** Получите его после `oc login`:

```bash
export NETINSPECT_TOKEN=$(oc whoami -t)
```

Токен **не передаётся аргументом** командной строки, чтобы не попасть в историю
shell. Порядок поиска:

1. `--token-env ИМЯ` — имя переменной окружения с токеном;
2. переменная `NETINSPECT_TOKEN`;
3. интерактивный ввод (`getpass`, без эха).

Токен не пишется в логи, `repr`, тексты ошибок и HTML-отчёт; в отладочном логе
видна только маска `****` + последние 4 символа.

**Адрес API:** `--server https://api.cluster.example:6443` или `NETINSPECT_SERVER`
(узнать: `oc whoami --show-server`).

**CA:** `--ca-file ca.crt` или `NETINSPECT_CA`. Получить CA можно, например, так:

```bash
oc config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt
# или из ConfigMap, доступного всем аутентифицированным пользователям:
oc get configmap kube-root-ca.crt -n default -o jsonpath='{.data.ca\.crt}' > ca.crt
```

Если CA кластера уже в системном хранилище, `--ca-file` не нужен. Флаг
`--insecure` отключает проверку сертификата — только для отладки, с
предупреждением в stderr.

Прочее: `--timeout` (по умолчанию 15 с), `--proxy URL`. Без `--proxy` действуют
стандартные `HTTPS_PROXY` / `NO_PROXY`.

## Команды

### connect — проверка подключения

```bash
python -m netinspect connect --server https://api.cluster.example:6443 --ca-file ca.crt -n prod
```

Выводит версию кластера (`/version`), пользователя (`user.openshift.io/users/~`,
для «чистого» Kubernetes — `n/a`), найденные версии Istio API, признак OpenShift
и таблицу прав на `list` для каждого типа ресурса (через `SelfSubjectAccessReview`).

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
python -m netinspect graph -n prod -n staging --html report.html

# от хоста: все Gateway, VirtualService и Route, у которых совпадает хост (с учётом wildcard)
python -m netinspect graph -A --host api.example.com

# от конкретного ресурса
python -m netinspect graph -A --resource vs/prod/reviews
```

Пример вывода:

```
Gateway prod/public-gw  [*.example.com:443]  [tls SIMPLE]  [api.example.com:80]
├── VirtualService prod/reviews  [api.example.com]  [mesh]
│   ├── DestinationRule prod/reviews  [subset v1 ✓]  [subset v2 ✓]  (v1 ✓, v2 ✓)
│   └── Service prod/reviews  [9080/TCP]  (v1 :9080 80%, v2 :9080 20%)
│       └── EndpointSlice prod/reviews-abc12  [3 ready]
└── VirtualService prod/ratings  [ratings.example.com]
    └── DestinationRule prod/ratings  [subset v1 ✓]  [subset v3 ✗]  ⚠
```

Опции:

| Опция | Назначение |
|---|---|
| `--host H` / `--resource KIND/NS/NAME` | точка входа; без неё — весь граф |
| `-n NS` (несколько раз) / `-A` | namespace |
| `--from-dir DIR` | читать манифесты из каталога вместо кластера |
| `--html FILE` | сохранить HTML-отчёт |
| `--no-color` | без цветов (также `NO_COLOR=1` или вывод не в терминал) |
| `--cluster-domain D` | домен кластера, по умолчанию `cluster.local` |
| `-v` / `-vv` | подробный / отладочный лог |

Подграф от точки входа строится обходом в ширину отдельно вниз (по трафику) и
вверх (против трафика). Gateway, совпавший с `--host` по wildcard, добавляется в
граф, но не разворачивается — иначе в отчёт попали бы все VirtualService этого
Gateway.

**Коды выхода:** `0` — успешно, проблем нет; `1` — ошибка (подключение, права,
аргументы); `2` — граф построен, но найдены проблемы (удобно для CI).

### HTML-отчёт

Один самодостаточный файл: CSS и JS встроены, нет внешних скриптов, шрифтов и
CDN — открывается без сети. Возможности:

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
python -m netinspect graph --from-dir tests/fixtures -A --html out.html   # код выхода 2
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

Плюс `create` на `selfsubjectaccessreviews` (есть у всех аутентифицированных
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

Тесты не ходят в сеть: `ApiClient` проверяется подменой `urlopen`/opener, граф
строится через `DirectorySource` на фикстурах.

Структура:

```
netinspect/
  core/   — подключение (config, client, errors), discovery, access, реестр типов,
            fetcher (ClusterSource / DirectorySource), модели, хосты
  graph/  — builder (связи), traverse (подграфы), render_text, render_html
  ui/     — theme.py: палитра, единый источник цветов для HTML и консоли
```

`core` и `graph` не зависят от CLI и HTML. Новый тип ресурса добавляется одной
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

1. **Проверка дублей и конфликтов:** несколько VS на один хост и Gateway,
   несколько DR на один host, пересекающиеся Route. Граф и `hosts.py` уже дают
   всё нужное — проверки лягут отдельным модулем поверх `Graph`.
2. **Каталог диагностических команд:** для узла с проблемой — готовые команды
   `oc`/`istioctl` (`istioctl x describe`, `proxy-config routes`, `oc get endpointslices -l ...`)
   в консоли и в панели HTML-отчёта.
3. Учёт `ServiceEntry`, `exportTo`, `delegate`, `Sidecar`.
