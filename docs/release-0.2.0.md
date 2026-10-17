# v0.2.0 — Read-only monitoring MCP

Добавлен MCP-интерфейс к SQLite коллектора: stdio и Streamable HTTP через
официальный Python SDK 2.3.0. Десять инструментов покрывают инвентарь, текущие
значения, историю, временные ряды, потребителей, события, состояние сбора,
каталог метрик, диагностические находки и контекст LLM-отчёта.

Историческая аналитика сохраняет разницу между отсутствием данных и нулём,
не интерполирует неизвестное распределение трафика и не суммирует звенья цепочки.
Все инструменты имеют JSON Schema и structured output, ограничения запросов и
read-only транзакции. Схема SQLite v1 совместима без миграции.

HTTP требует bearer token из приватного файла, слушает только loopback и
проверяет Host/Origin; добавлен отдельный systemd-шаблон. HTTPS reverse proxy
настраивается отдельно. OAuth, Telegram-адаптер, rollups и lifecycle incidents
не входят в этот релиз. Аномалии — объяснимые находки в выбранном окне,
не автоматически установленные причины и не история открытых/устранённых incidents.

Проверки: аналитические regression tests, официальный MCP-клиент для всех tools,
реальные stdio/HTTP процессы, auth/Origin/Host/body limits, Windows/Linux,
Python 3.11/3.12 в CI, Linux smoke, compile/dependency checks, ревью и Gitleaks
для working tree, staged diff, Git history и распакованного ZIP. ZIP имеет SHA256.

Production VM не изменялась. Установка MCP-зависимостей: `pip install -r requirements-mcp.lock`.
Инструкции запуска и контракты: `README.md`, `docs/mcp.md`.
