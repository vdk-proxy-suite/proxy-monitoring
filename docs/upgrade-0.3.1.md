# Обновление с v0.3.0 до v0.3.1

Миграции БД коллектора и OAuth не нужны. Сохраняйте `config.json`, `oauth.json`,
`owner.hash` и обе БД. Не повторяйте инициализацию пароля или replay логов.
Ни Caddy, ни сами прокси останавливать не нужно.

На VM из-под пользователя с sudo:

```bash
sudo -v
bash <<'BASH'
set -euo pipefail
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
base=https://github.com/vdk-proxy-suite/proxy-monitoring/releases/download/v0.3.1
curl -fL --retry 3 "$base/proxy-monitoring-0.3.1.zip" -o "$work_dir/proxy-monitoring-0.3.1.zip"
curl -fL --retry 3 "$base/proxy-monitoring-0.3.1.zip.sha256" -o "$work_dir/proxy-monitoring-0.3.1.zip.sha256"
(cd "$work_dir" && sha256sum --check proxy-monitoring-0.3.1.zip.sha256)
unzip -q "$work_dir/proxy-monitoring-0.3.1.zip" -d "$work_dir"
sudo cp -a /etc/proxy-monitoring/oauth.json "/etc/proxy-monitoring/oauth.json.pre-0.3.1.$(date -u +%Y%m%dT%H%M%SZ)"
sudo systemctl stop proxy-monitoring-mcp-oauth.service
sudo systemctl stop proxy-monitoring.service
sudo cp -a "$work_dir/proxy-monitoring-0.3.1/." /opt/proxy-monitoring/
sudo chown -R root:root /opt/proxy-monitoring
sudo python3 - <<'PY'
import json
from pathlib import Path
p = Path('/etc/proxy-monitoring/oauth.json')
data = json.loads(p.read_text())
callback = 'http://127.0.0.1/callback'
if callback not in data['redirect_uris']:
    data['redirect_uris'].append(callback)
    p.write_text(json.dumps(data, indent=2) + '\n')
PY
cd /opt/proxy-monitoring
sudo -u proxy-monitor venv/bin/python -m proxy_monitoring --config /etc/proxy-monitoring/config.json validate
sudo -u proxy-monitor venv/bin/python -c 'from pathlib import Path; from proxy_monitoring.oauth_config import OAuthConfig; c = OAuthConfig.load(Path("/etc/proxy-monitoring/oauth.json")); c.read_owner_hash(); print("OAuth config OK")'
sudo systemctl start proxy-monitoring.service
sudo systemctl start proxy-monitoring-mcp-oauth.service
cat VERSION
sudo systemctl is-active proxy-monitoring.service proxy-monitoring-mcp-oauth.service
BASH
```

При ошибке остановитесь: блок не выполняет автоматический rollback. Зависимости
v0.3.0 не изменились. OAuth-служба требует активный коллектор, поэтому запускается
после него. Старт службы перечитывает изменённый allowlist.

В клиенте Codex добавьте Streamable HTTP сервер с URL
`https://monitor.example.com/mcp` (замените домен своим), затем Authenticate. Если клиент показывает
другой callback path, внесите его точный URL в `redirect_uris` через `sudoedit`
и перезапустите OAuth-службу. Адрес `localhost` не заменяет `127.0.0.1`.
Не подставляйте loopback callback в `issuer` или URL самого MCP.

Без токена `/mcp` должен отвечать 401. После входа и согласия клиент должен
получить список из 10 инструментов. Это проверяет авторизацию; один лишь
успешный discovery её не подтверждает.
