# Proxy Monitoring 0.3.0

0.3.0 добавляет OAuth для удалённого MCP: вход владельца, явное согласие,
Authorization Code + PKCE, discovery, refresh/revoke и отдельную auth DB.
Настройка HTTPS и подключение клиента: [docs/oauth.md](docs/oauth.md).

0.2.1 исправляет чтение 3proxy-логов с не-UTF-8 байтами в клиентском тексте.
Числовые поля остаются строго проверяемыми, byte offsets не меняются. Уже
пропущенные старой версией строки автоматически не перечитываются; существующая
история и cursors сохраняются. `log_pending_bytes` означает недочитанный лог,
а не сбой декодирования.

0.2.2 добавляет проверенный профиль `3proxy_monitor_v1`, исправляет направления
upload/download в этом формате и позволяет восстановить NULL-байты и пропущенные
строки из сохранившихся plain-логов без дубликатов. Можно обновиться сразу с 0.2.0.
Порядок обновления и восстановления: [docs/upgrade-0.2.2.md](docs/upgrade-0.2.2.md).

Локальный Linux-сборщик телеметрии нескольких инстансов Telemt и 3proxy в SQLite.
Коллектор не зависит от Telegram и работает без MCP-клиента. Python 3.11+,
обязательных внешних runtime-зависимостей у коллектора нет. Для MCP используется
официальный SDK `mcp==2.3.0`; проверенные зависимости закреплены в `requirements-mcp.lock`.

## Возможности релиза

Реализованы сбор, постоянное хранилище, read-only CLI, retention и systemd-шаблоны.
В 0.2.0 добавлены read-only MCP (stdio и Streamable HTTP), историческая аналитика,
10 инструментов с JSON Schema/structured output и диагностические правила.
Telegram-адаптер, сезонные аномалии, lifecycle incidents и rollups пока не реализованы.
Существующий `proxy-monitor-bot` остаётся самостоятельным проектом; его БД не
импортируется и не изменяется.

## MCP

После настройки и запуска коллектора:

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements-mcp.lock
venv/bin/python -m proxy_monitoring --config config.json mcp
```

Это stdio-сервер: stdout занят MCP-протоколом, команды shell туда не вводятся.
Настройте MCP-клиент на запуск этой команды с абсолютными путями и рабочим
каталогом проекта. В Windows используется `venv\Scripts\python.exe`.
Для удалённой VM можно запускать stdio-команду через SSH с отключённым TTY.

Для удалённых клиентов с OAuth используйте [OAuth-режим](docs/oauth.md).
Альтернативный HTTP bearer-режим требует приватный файл с криптографически случайным bearer token
длиной 32–512 ASCII-символов без пробелов (например `secrets.token_urlsafe(32)`).
Не передавайте токен в CLI arguments или Git. На Linux файл должен иметь mode 0600.

```bash
venv/bin/python -m proxy_monitoring --config config.json mcp \
  --transport streamable-http --host 127.0.0.1 --port 9000 \
  --token-file /etc/proxy-monitoring/mcp.token
```

Endpoint: `http://127.0.0.1:9000/mcp`, заголовок `Authorization: Bearer <token>`.
Публичный bind запрещён. Для внешнего доступа нужны HTTPS reverse proxy и клиент,
умеющий передавать bearer header. Reverse proxy должен сохранять Authorization,
переписывать Host на `127.0.0.1:9000` и не записывать Authorization в access logs.
Если клиент посылает Origin, задайте разрешённый origin:
`--public-origin https://monitor.example.com`. Иначе любой Origin отклоняется.
Этот вариант использует static bearer authentication. Для OAuth discovery вместо
`--token-file` укажите `--oauth-config`, как описано в docs/oauth.md.
TLS, DNS и ingress автоматически не настраиваются.

Шаблон отдельной службы: `systemd/proxy-monitoring-mcp.service`. Он использует
venv, запускается после коллектора и ограничивает каталог БД чтением.
Сначала установите зависимости в root-owned venv и создайте token-файл с доступом
на чтение только runtime-пользователю. Шаблон не устанавливается автоматически.
БД v0.1.0 читается напрямую без миграции; MCP не записывает её и не запускает сбор.

Инструменты, параметры, семантика и ограничения: [docs/mcp.md](docs/mcp.md).

## Источники

- **Telemt:** loopback `/metrics`, поддержка нескольких экземпляров, пользовательские
  сессии и байты, accepted TCP, bad connections, handshake timeouts, upstream
  success/fail, uptime. Поддерживаются имена байтов с `_total` и старые aliases;
  при наличии обоих выбирается `_total`. Известные имена отсутствующих метрик
  возвращаются в warnings, не превращаются в нули
- **3proxy:** `monitor_v1` и legacy UTC-логи, инкрементальное чтение всех plain-файлов
  по glob, rename-ротация, обнаружение truncate по размеру/префиксу, атомарные
  cursor и записи. Записи обозначают log events, а не число TCP-соединений
- **Linux:** CPU ticks по режимам, load average, RAM/Swap, disk/inodes, сеть
  по интерфейсам кроме loopback. Проценты CPU и скорости вычисляются потребителем
  из интервалов; абсолютные CPU ticks не являются процентом загрузки
- **Сокеты Telemt:** TCP listen/established/close_wait по заданным локальным портам
  в network namespace сборщика. Это снимок сокетов, не число авторизованных сессий

## Быстрый запуск без установки пакета

```bash
cp config.example.json config.json
# Отредактируйте host_id, database, units, log_glob и ports под свою машину
python3 -m proxy_monitoring --config config.json validate
python3 -m proxy_monitoring --config config.json collect --once
python3 -m proxy_monitoring --config config.json health
python3 -m proxy_monitoring --config config.json current
python3 -m proxy_monitoring --config config.json collect
```

Пути `database` относительно файла конфигурации; `log_glob` должен быть абсолютным.
Пример содержит условный host и пример портов, не является production-профилем.
Для ещё одного инстанса добавьте элемент `sources` с уникальным `id` и своим unit.
После смены endpoint, пути, ports или семантики источника задайте **новый source id**:
иначе старые baselines могли бы смешаться с другим источником. Исключение — переход
только `byte_semantics` из unknown/delta в `3proxy_monitor_v1`: id сохраняется,
остальные поля должны совпадать. Старые данные
остаются до retention, но выключенные источники не участвуют в health/current.

`collect --once`: код 0 — все источники обработаны, возможно с предупреждениями;
1 — хотя бы один источник недоступен; 2 — ошибка конфигурации/БД/запуска.
`health`: код 1 также означает partial/stale. `validate` проверяет структуру,
но не проверяет доступность sources. В CLI ошибки обезличены, подробные machine
codes и warnings находятся в `health` и таблице `runs`.

## Семантика 3proxy

Для формата 3proxy-setup `monitor_v1` укажите `byte_semantics: "3proxy_monitor_v1"`.
Это явное подтверждение профиля с `%O|%I` на позициях 15/16 (нумерация от нуля):
upload к upstream, download от upstream. В upstream 3proxy 0.9.5 счётчики
сбрасываются после форматирования записи, включая промежуточные `logdump`.
Профиль проверен реальным loopback-тестом с асимметричным трафиком и logdump.
Неподходящие legacy-строки под этим профилем отклоняются с `profile_format_mismatch`.
Префикс `v1|` сам по себе не доказывает соответствие произвольного пользовательского формата.

Без явного профиля остаётся безопасное значение `unknown` (NULL-байты).
Режим `delta` оставлен для отдельно проверенных форматов; порядок legacy-полей
не изменён. Число строк никогда не называется
числом соединений. Байты учитываются и при ненулевом коде результата, если
семантика формата подтверждена: ошибка не отменяет уже переданные байты.

Время учёта — timestamp записи. Долгая сессия может записать трафик лишь при
закрытии; такой объём не доказывает фактическую скорость в минуту закрытия.
Сырые строки, IP, usernames, адреса назначения и URL из логов не сохраняются.
Имена пользователей из allowlisted Telemt labels сохраняются для аналитики;
не используйте секреты в именах пользователей.

## Постоянный запуск через systemd

Шаблон: `systemd/proxy-monitoring.service`. Он не устанавливается автоматически.
Разместите код root-owned в `/opt/proxy-monitoring`, конфигурацию в
`/etc/proxy-monitoring/config.json`, создайте отдельного непривилегированного
пользователя `proxy-monitor`. В конфигурации задайте
`"database": "/var/lib/proxy-monitoring/monitor.db"`. StateDirectory создаётся
systemd с правами 0700. Сервис использует системный Python 3.11+ без pip-пакетов.

Дайте пользователю только чтение нужных логов и traversal их каталогов через
выделенную группу/ACL; обеспечьте эти права и для новых файлов после ротации.
Нужен доступ к `systemctl show` и `/proc` целевых Telemt-процессов для epoch.
При ограниченном `/proc` коллектор сообщит ошибку, не подменит epoch текущим временем.
Не давайте права перезапуска/изменения прокси. Открывать ingress-порт не требуется.

После подготовки окружения:

```bash
sudo cp systemd/proxy-monitoring.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-monitoring.service
sudo -u proxy-monitor python3 -m proxy_monitoring --config /etc/proxy-monitoring/config.json health
```

Последнюю команду запускайте из `/opt/proxy-monitoring`. Отдельный online health
сборщика не доказывает работоспособность прокси end-to-end.

## Хранение и качество

- SQLite WAL/FULL, foreign keys, один писатель с OS-lock, транзакция на снимок/пакет логов
- UTC milliseconds; integer counters сохраняют точность выше 2^53
- Первый снимок — baseline, restart/decrease — reset с NULL delta
- Сбой/пропуск между снимками — gap; положительная delta относится ко всему
  интервалу и не распределяется произвольно по минутам
- Boot ID + systemd InvocationID + PID + process start ticks определяют epoch Telemt
- `current` возвращает время/возраст, stale и признак отсутствия в последнем run
- Хранение сырых samples/log events по умолчанию 7 дней, очистка раз в час
- Cursors и последние counter baselines сохраняются после очистки, чтобы не
  перечитывать старые логи повторно. Серии и cursors имеют отдельный жизненный цикл

Очистка освобождает страницы для повторного использования, но не уменьшает
файл на диске автоматически. Размер БД зависит от числа рядов и объёма логов;
перед production оцените рост. История старше retention удаляется без rollup.

## Ограничения сбора

- Нет gzip-backfill: `.gz` пропускаются с warning; используйте plain rename-ротацию
  и достаточную задержку сжатия. После долгого простоя возможно неполное покрытие
- `copytruncate` может потерять байты; идентичный truncate/regrow между опросами
  не всегда обнаружим. Встроенная дедупликация гарантируется для известных
  generation+offset, а не для произвольных скопированных архивов
- Cursor продвигается через некорректную завершённую строку с parse warning;
  исходный лог остаётся источником для ручной диагностики
- Строка больше 64 KiB блокирует пакет с явной ошибкой; исходный файл не меняется
- Сбор последовательный, источники имеют bounded операции; фактический период
  может быть больше заданного при медленных источниках. Интервалы хранят реальные timestamps
- Нет точного учёта новых TCP accepts, UDP relay flows или сетевого трафика по портам
- Сокеты атрибутируются по порту, без bind address/PID; конфликты портов между
  адресами/namespace требуют отдельного адаптера. Не складывайте снимки дублирующихся портов
- Общие process counters Telemt не распределяются по listener-портам
- Нет Telemt API, HAProxy, journal, PSI, route graph или LLM-анализатора
- Для сетевых интерфейсов epoch — boot; reset с возвращением значения выше
  предыдущего между опросами не обнаруживается. Такие сетевые delta — наблюдаемые
- Бэкап работающей SQLite делайте SQLite backup API, не одиночным копированием `.db`

## Проверки и релиз

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q proxy_monitoring tests tools
python3 tools/smoke_linux.py
python3 tools/build_archive.py --output dist
```

Для полного набора тестов используйте Python из venv с `requirements-mcp.lock`.
Тесты MCP запускают реальный stdio-процесс, локальный HTTP endpoint и официальный
SDK-клиент; после выполнения все созданные процессы завершаются.

Unit/integration tests используют временные БД, синтетические логи и loopback HTTP.
`smoke_linux.py` дополнительно проверяет реальный `/proc` и CLI на Linux, не
останавливает службы и не обращается к production-прокси. CI запускает тесты на
Linux и Windows. Спецификация реализованной БД: [docs/storage.md](docs/storage.md).

Следующий этап: Telegram-адаптер и rollups.
Все интерфейсы сохраняют различия
между application/network traffic, log events/sessions/TCP sockets и gaps/zeros.
