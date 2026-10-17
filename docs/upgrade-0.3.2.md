# Обновление OAuth с v0.3.1 до v0.3.2

Исправляется браузерная отправка формы и переход к callback. Миграции обеих БД,
сброс пароля, переустановка runtime-зависимостей и replay логов не нужны.
Сохраните существующие `config.json`, `oauth.json`, `owner.hash` и данные.

На VM из-под пользователя с sudo:

```bash
sudo -v
bash <<'BASH'
set -euo pipefail
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
base=https://github.com/vdk-proxy-suite/proxy-monitoring/releases/download/v0.3.2
curl -fL --retry 3 "$base/proxy-monitoring-0.3.2.zip" -o "$work_dir/proxy-monitoring-0.3.2.zip"
curl -fL --retry 3 "$base/proxy-monitoring-0.3.2.zip.sha256" -o "$work_dir/proxy-monitoring-0.3.2.zip.sha256"
(cd "$work_dir" && sha256sum --check proxy-monitoring-0.3.2.zip.sha256)
unzip -q "$work_dir/proxy-monitoring-0.3.2.zip" -d "$work_dir"
sudo systemctl stop proxy-monitoring-mcp-oauth.service
sudo systemctl stop proxy-monitoring.service
sudo cp -a "$work_dir/proxy-monitoring-0.3.2/." /opt/proxy-monitoring/
sudo chown -R root:root /opt/proxy-monitoring
cd /opt/proxy-monitoring
sudo -u proxy-monitor venv/bin/python -m proxy_monitoring --config /etc/proxy-monitoring/config.json validate
sudo -u proxy-monitor venv/bin/python -c 'from pathlib import Path; from proxy_monitoring.oauth_config import OAuthConfig; c = OAuthConfig.load(Path("/etc/proxy-monitoring/oauth.json")); c.read_owner_hash(); print("OAuth config OK")'
sudo systemctl start proxy-monitoring.service
sudo systemctl start proxy-monitoring-mcp-oauth.service
cat VERSION
sudo systemctl is-active proxy-monitoring.service proxy-monitoring-mcp-oauth.service
BASH
```

При ошибке остановитесь на этом шаге: автоматического rollback нет. Caddy и
сами прокси не останавливаются. Этот блок не меняет конфигурации или пароль.

Закройте старую вкладку входа. В Codex снова выберите Authenticate у своего
Streamable HTTP сервера. URL MCP: `https://monitor.example.com/mcp` (подставьте
свой домен). Пароль вводится на странице владельца мониторинга, а не в поле
client secret или bearer token. После согласия браузер возвращает управление
локальному OAuth callback клиента. Сервер должен показать 10 инструментов.

Для прямого Codex callback в `redirect_uris` должен быть
`http://127.0.0.1/callback` (или точный путь, который использует ваш клиент).
Если он ещё не добавлен, следуйте разделу callback в [oauth.md](oauth.md).
Без токена `/mcp` по-прежнему отвечает 401 — это ожидаемая проверка защиты.
