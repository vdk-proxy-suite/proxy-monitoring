# Обновление коллектора до 0.2.2

Можно перейти сразу с 0.2.0, устанавливать 0.2.1 отдельно не нужно. Выполнять на
VM из-под администратора с sudo. Прокси не останавливаются. Если MCP тоже работает,
остановите его на время обновления/восстановления и запустите после проверки.

## Получить и установить релиз

```bash
sudo -v
bash <<'BASH'
set -euo pipefail
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
base=https://github.com/vdk-proxy-suite/proxy-monitoring/releases/download/v0.2.2
curl -fL --retry 3 "$base/proxy-monitoring-0.2.2.zip" -o "$work_dir/proxy-monitoring-0.2.2.zip"
curl -fL --retry 3 "$base/proxy-monitoring-0.2.2.zip.sha256" -o "$work_dir/proxy-monitoring-0.2.2.zip.sha256"
(cd "$work_dir" && sha256sum --check proxy-monitoring-0.2.2.zip.sha256)
unzip -q "$work_dir/proxy-monitoring-0.2.2.zip" -d "$work_dir"

sudo systemctl stop proxy-monitoring.service
sudo install -d -o proxy-monitor -g proxy-monitor -m 0700 /var/lib/proxy-monitoring/backups
sudo -u proxy-monitor python3 - <<'PY'
from contextlib import closing
from datetime import datetime, timezone
import sqlite3
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
with closing(sqlite3.connect('file:/var/lib/proxy-monitoring/monitor.db?mode=ro', uri=True)) as src:
    with closing(sqlite3.connect('/var/lib/proxy-monitoring/backups/pre-0.2.2-' + stamp + '.db')) as dst:
        src.backup(dst)
print('SQLite backup created')
PY
sudo cp -a /etc/proxy-monitoring/config.json "/etc/proxy-monitoring/config.json.pre-0.2.2.$(date -u +%Y%m%dT%H%M%SZ)"
sudo cp -a "$work_dir/proxy-monitoring-0.2.2/." /opt/proxy-monitoring/
sudo chown -R root:root /opt/proxy-monitoring
BASH
```

При ошибке после остановки коллектора устраните её до следующего шага. БД и
конфигурация находятся вне каталога приложения и не заменяются архивом.

## Включить профиль для штатных логов 3proxy-setup

Следующая команда предназначена для двух инстансов на одном хосте со штатным
`monitor_v1`. Она не меняет конфигурацию 3proxy, ports, source ids или пути.
Если logformat на хосте изменён вручную, сначала проверьте порядок `%O|%I`:
`Gv1|%t|%.|%D|%N|%p|%E|%U|%C|%c|%R|%r|%Q|%q|%n|%O|%I|%h|%T`.

```bash
sudo python3 - <<'PY'
import json
from pathlib import Path
p = Path('/etc/proxy-monitoring/config.json')
cfg = json.loads(p.read_text())
selected = {'3proxy-main', '3proxy-local'}
found = {s['id'] for s in cfg['sources'] if s['id'] in selected and s['kind'] == '3proxy'}
if found != selected:
    raise SystemExit('Expected both 3proxy sources; config unchanged')
expected = 'logformat "-|+_Gv1|%t|%.|%D|%N|%p|%E|%U|%C|%c|%R|%r|%Q|%q|%n|%O|%I|%h|%T"'
for name in ('main', 'local'):
    proxy_cfg = Path('/etc/3proxy-setup/instances') / name / '3proxy.cfg'
    formats = [line.strip() for line in proxy_cfg.read_text().splitlines()
               if line.strip().startswith('logformat ')]
    if formats != [expected]:
        raise SystemExit('Unexpected 3proxy logformat; collector config unchanged')
for source in cfg['sources']:
    if source['id'] in selected:
        source['byte_semantics'] = '3proxy_monitor_v1'
p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + '\n')
PY
```

## Восстановить доступную историю и запустить сбор

```bash
bash <<'BASH'
set -euo pipefail
cd /opt/proxy-monitoring
sudo -u proxy-monitor python3 -m proxy_monitoring --config /etc/proxy-monitoring/config.json validate
sudo -u proxy-monitor python3 -m proxy_monitoring --config /etc/proxy-monitoring/config.json replay-3proxy \
  --source-id 3proxy-main --source-id 3proxy-local
sudo systemctl start proxy-monitoring.service
sleep 35
sudo -u proxy-monitor python3 -m proxy_monitoring --config /etc/proxy-monitoring/config.json health
BASH
```

Replay не сбрасывает статистику Telemt и не создаёт новые source ids. Он читает
только выбранные существующим glob plain-файлы, сохраняет generation+offset и
обновляет байты существующих записей. Записи, ещё не прочитанные раньше, добавляются.
`remaining_unknown_records` показывает данные, которых нет в доступных логах или
которые не удалось восстановить. Не удаляйте БД и не копируйте/распаковывайте старые
архивы в рабочий glob: смена файловой идентичности может создать дубликаты.

Если replay прервался, повторите его с остановленным коллектором. Обработанные
пакеты транзакционны; повторный запуск безопасен для неизменённых файлов.
Если replay обнаруживает truncate/replacement, он останавливается до сброса cursor.
Сначала выполните обычный цикл коллектора, чтобы зарегистрировать новое поколение,
затем повторите replay с остановленной службой.
`log_pending_bytes` может кратковременно появляться при догоняющем чтении или
неполной последней строке. Это не означает ошибку учёта байтов.

Основание профиля: [3proxy 0.9.5 log.c](https://github.com/3proxy/3proxy/blob/0.9.5/src/log.c)
(`%O`/`%I`, `clearstat` после форматирования) и
[sockmap.c](https://github.com/3proxy/3proxy/blob/0.9.5/src/sockmap.c)
(вызов логирования по порогу). Проверка runtime: `tools/probe_3proxy_accounting.py`.
