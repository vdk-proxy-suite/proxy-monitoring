# Proxy Monitoring 0.1.0

Локальный Linux-сборщик телеметрии нескольких инстансов Telemt и 3proxy в SQLite.
Коллектор не зависит от Telegram и работает без MCP-клиента. Python 3.11+,
обязательных внешних runtime-зависимостей нет.

## Границы первого релиза

Реализованы сбор, постоянное хранилище, read-only CLI, retention и systemd-шаблон.
MCP-сервер, Telegram-адаптер, аномалии, исторические сводки и rollups пока не
реализованы. Это основа мониторинга, а не готовый удалённый MCP endpoint.
Существующий `proxy-monitor-bot` остаётся самостоятельным проектом; его БД не
импортируется и не изменяется.

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
иначе старые baselines могли бы смешаться с другим источником. Старые данные
остаются до retention, но выключенные источники не участвуют в health/current.

`collect --once`: код 0 — все источники обработаны, возможно с предупреждениями;
1 — хотя бы один источник недоступен; 2 — ошибка конфигурации/БД/запуска.
`health`: код 1 также означает partial/stale. `validate` проверяет структуру,
но не проверяет доступность sources. В CLI ошибки обезличены, подробные machine
codes и warnings находятся в `health` и таблице `runs`.

## Семантика 3proxy

`byte_semantics: "unknown"` по умолчанию: байты сохраняются как NULL. Укажите
`"delta"` только после проверки, что каждая строка вашего формата содержит
самостоятельный объём, а не повторный накопительный итог. `logdump`, служебные
записи и UDP могут менять смысл строк. Число строк никогда не называется
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

## Ограничения 0.1.0

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

Unit/integration tests используют временные БД, синтетические логи и loopback HTTP.
`smoke_linux.py` дополнительно проверяет реальный `/proc` и CLI на Linux, не
останавливает службы и не обращается к production-прокси. CI запускает тесты на
Linux и Windows. Спецификация реализованной БД: [docs/storage.md](docs/storage.md).

Следующий этап: исторический query layer и MCP read-only transport; затем
Telegram-адаптер того же query layer. Все интерфейсы должны сохранять различия
между application/network traffic, log events/sessions/TCP sockets и gaps/zeros.
