# v0.1.0 — SQLite collector foundation

Первый релиз `proxy-monitoring` отделяет сбор телеметрии от Telegram и будущего MCP.

- Несколько источников Telemt `/metrics` и 3proxy logs; метрики Linux-хоста
- SQLite WAL, integer counters, restart epochs, baseline/reset/gap semantics
- Транзакционное чтение логов с cursor, rename-ротацией и защитой от повторного учёта
- Read-only `health`/`current` CLI, JSON config, systemd template, retention
- Тесты Windows/Linux, Linux smoke, CI и воспроизводимый allowlisted ZIP с SHA256

Это релиз сборщика: MCP-сервер и Telegram-интерфейс ещё не реализованы.
Нет rollups: история старше retention удаляется. Gzip-backfill и точный live
трафик 3proxy по портам не поддерживаются. Byte semantics логов по умолчанию
unknown; настройка delta требует проверки формата конкретного инстанса.

Проверки перед публикацией: unit/integration suite на Windows и Linux, compileall,
реальный Linux /proc/CLI smoke, ревью транзакций/epoch/ротации/приватности,
gitleaks working tree/index/history/extracted archive, проверка ZIP и checksum.
Production VM не изменялась; проверка установленного Telemt/3proxy остаётся
отдельным этапом внедрения.
