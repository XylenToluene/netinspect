# Тестовые манифесты для кластера

Набор YAML-манифестов, чтобы проверить netinspect на **настоящем тестовом кластере**
(OpenShift или Kubernetes с Istio). Всё создаётся в отдельном namespace
`netinspect-demo` и удаляется одной командой.

В наборе есть рабочие цепочки и **намеренные ошибки**: netinspect должен их найти.

## Что внутри

| Файл | Что создаёт |
|---|---|
| `00-namespace.yaml` | namespace `netinspect-demo` с включённой инъекцией sidecar |
| `01-workloads.yaml` | Deployment reviews v1/v2, ratings v1, productpage v1 и Service reviews, ratings, productpage, details |
| `02-gateway.yaml` | Gateway `demo-gateway` для `*.demo.example.com` |
| `03-destinationrules.yaml` | DestinationRule с subsets (reviews: v1, v2, v3; ratings: v1), DR для внешнего API, DR с опечаткой |
| `04-virtualservices.yaml` | VirtualService: рабочие, с отсутствующим subset, с несуществующим Gateway, исходящие на внешние хосты |
| `05-serviceentries.yaml` | рабочий ServiceEntry для внешнего API |
| `05b-serviceentries-invalid.yaml` | ошибочные ServiceEntry (кластер может их отклонить, см. ниже) |
| `06-envoyfilters.yaml` | EnvoyFilter: на сервис, на subset v2, на шлюз и «сирота» |
| `07-route.yaml` | OpenShift Route на productpage (только OpenShift) |

## Что должен показать netinspect

| Объект | Ожидаемый результат |
|---|---|
| VirtualService `reviews` | маршрут 80% → subset `reviews:v1`, 20% → `reviews:v2` → Service reviews |
| Subset `reviews:v3` | пометка «не используется» |
| DestinationRule `ratings` | ✗ `subset v3 отсутствует` — VirtualService ratings ссылается на v3 |
| DestinationRule `revews-typo` | ✗ host `revews…`: Service не найден |
| Gateway `old-gateway` | ✗ не найден (ссылка из VirtualService legacy) |
| Service `details` | ✗ нет endpoints (подов нет) |
| VirtualService `payments-egress` | → ServiceEntry `payments` (+ DestinationRule `payments`, TLS) |
| внешний хост `api.analytics.example.net` | пометка «нет ServiceEntry» |
| ServiceEntry `legacy-db` | ✗ STATIC без endpoints |
| ServiceEntry `partner-apis` | ✗ DNS с хостом-звёздочкой без endpoints |
| EnvoyFilter `reviews-lua` | применяется к Service reviews |
| EnvoyFilter `reviews-v2-lua` | применяется к subset `reviews:v2` |
| EnvoyFilter `gateway-lua` | применяется к Gateway `demo-gateway` |
| EnvoyFilter `orphan-filter` | ✗ selector ни с чем не совпадает |

## Как применить на кластер

Нужны права на создание namespace (или попросите администратора создать
`netinspect-demo` и выдать вам права в нём).

```bash
oc login ...                                  # или kubectl с нужным контекстом
oc apply -f tests/manifests/00-namespace.yaml
oc apply -f tests/manifests/
```

**OpenShift Service Mesh 2.x:** namespace нужно добавить в mesh: в объект
`ServiceMeshMemberRoll` (обычно `default` в `istio-system`) в список `members`
добавьте `netinspect-demo`. Без этого Istio-ресурсы создадутся, но sidecar в поды
не попадут. Для работы netinspect это неважно: он читает манифесты.

**Ошибки при apply.** Валидатор Istio может отклонить файл `05b-serviceentries-invalid.yaml`
(ServiceEntry `legacy-db` и `partner-apis`). Это ожидаемо: остальные объекты
создадутся. Эти два случая видны при проверке из папки (ниже).

**Образ.** Deployment используют `registry.access.redhat.com/ubi9/httpd-24`. Если
реестр недоступен, замените `image` в `01-workloads.yaml` на любой доступный
веб-сервер, слушающий порт 8080.

Затем:

```bash
python -m netinspect graph -n netinspect-demo   # нужен NETINSPECT_SERVER и токен
python -m netinspect serve                      # и откройте «Граф связей»
```

## Проверка без кластера

Манифесты можно разобрать прямо из папки. Нужен PyYAML: без него YAML-файлы
пропускаются с предупреждением.

```bash
python -m netinspect graph --from-dir tests/manifests -A
python -m netinspect serve
```

При чтении из папки у **всех** сервисов будет «нет endpoints»: EndpointSlice
создаёт сам кластер, когда поднимаются поды. На кластере это сообщение останется
только у `details`.

## Как удалить

```bash
oc delete namespace netinspect-demo
```
