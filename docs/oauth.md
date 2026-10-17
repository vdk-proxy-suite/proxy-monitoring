# OAuth для удалённого MCP

Режим OAuth предназначен для одного владельца мониторинга. Владелец вводит пароль
на странице своего сервера и явно разрешает клиенту читать всю телеметрию.
Регистрация клиента сама по себе доступа не даёт. Пароль не передаётся клиенту.
Коллектор продолжает работать отдельно; схема SQLite с телеметрией не меняется.

Поддерживаются Authorization Code с S256 PKCE, динамическая регистрация публичных
клиентов (`token_endpoint_auth_method=none`), OAuth discovery, `resource`, scopes,
ротация refresh tokens и отзыв доступа. Клиент должен передавать точный `resource`
как в authorize, так и в token/refresh запросах. CIMD, client credentials, OIDC,
внешние identity providers и несколько владельцев в этой версии не реализованы.
Это автономная реализация входа владельца, а не интеграция с корпоративным SSO.

## Подготовка Linux

Нужен собственный DNS-домен с HTTPS, ведущий на VM. MCP слушает только loopback
`127.0.0.1:9000`; TLS завершает reverse proxy. Callback URI требует HTTPS, кроме
локального HTTP callback на буквальный `127.0.0.1` или `[::1]` (начиная с v0.3.1).
На этом этапе не нужно менять настройки или перезапускать 3proxy/Telemt.

После установки релиза в `/opt/proxy-monitoring`:

```bash
cd /opt/proxy-monitoring
sudo python3 -m venv venv
sudo venv/bin/python -m pip install -r requirements-mcp.lock
sudo install -d -o proxy-monitor -g proxy-monitor -m 0700 /var/lib/proxy-monitoring-auth
sudo install -o root -g proxy-monitor -m 0640 docs/oauth.example.json /etc/proxy-monitoring/oauth.json
sudoedit /etc/proxy-monitoring/oauth.json
```

Замените `issuer` на HTTPS origin без завершающего `/`. В `redirect_uris` укажите
точные callback URL ваших клиентов, без wildcard. Для ChatGPT пример содержит
стабильный callback; сервер объявляет и возвращает `iss`. Если интерфейс клиента
показывает индивидуальный callback, добавьте именно его. Это соответствует
[требованиям ChatGPT OAuth](https://developers.openai.com/plugins/build/auth).
Другие клиенты должны поддерживать public-client DCR, PKCE и resource indicators.
Работу через конкретный аккаунт ChatGPT проверяют после настройки публичного HTTPS.

Для Codex разрешите `http://127.0.0.1/callback` (в новом примере он уже включён).
Это адрес браузера/локального слушателя на компьютере с Codex, а не адрес VM.
Согласно RFC 8252 порт может отличаться между регистрацией и авторизацией;
host, path и query должны совпадать. Для IPv6 отдельно разрешите
`http://[::1]/callback`. `localhost`, внешние HTTP-адреса, другие IP и wildcard
не поддерживаются. Если клиент использует `/callback/<id>`, добавьте именно этот
путь; разрешение `/callback` не разрешает все дочерние пути. Полный фактический
callback, включая порт, затем точно проверяется при обмене кода на токен.
`issuer` и `resource` MCP остаются HTTPS. После изменения allowlist перезапустите
только `proxy-monitoring-mcp-oauth.service`, затем повторите Authenticate в клиенте.

Создайте пароль интерактивно (не передавайте его аргументом команды или в JSON):

```bash
cd /opt/proxy-monitoring
sudo venv/bin/python -m proxy_monitoring oauth-init-owner --oauth-config /etc/proxy-monitoring/oauth.json
sudo chown proxy-monitor:proxy-monitor /etc/proxy-monitoring/owner.hash
sudo chmod 0600 /etc/proxy-monitoring/owner.hash
```

Команда отказывается перезаписывать существующий файл. Файл содержит salted scrypt
hash. Используйте отдельный длинный пароль, не пароль SSH или прокси. На Windows
ограничьте ACL каталога auth DB и файла hash учётной записью сервера: POSIX modes
на этой платформе не обеспечивают эквивалентной защиты.

## Reverse proxy и служба

Пример Caddy site (подставьте свой домен; Caddy должен уже быть установлен):

```caddyfile
monitor.example.com {
    request_body {
        max_size 64KB
    }
    reverse_proxy 127.0.0.1:9000
}
```

Сохраните исходный Host. Проксируйте весь origin, включая `/.well-known/*`,
`/authorize`, `/login`, `/register`, `/token`, `/revoke`, `/mcp`. Не включайте
access logs с query strings или телами запросов: authorize содержит state,
а token/login — чувствительные данные. Не добавляйте Basic Auth перед OAuth.
Ограничьте время чтения запроса и частоту запросов также на публичном reverse proxy.
Порт 9000 не открывается наружу. Не публикуйте ту же БД через второй незащищённый MCP.

Если уже работает прежняя bearer-служба на 9000, остановите только её:

```bash
sudo systemctl stop proxy-monitoring-mcp.service
sudo systemctl disable proxy-monitoring-mcp.service
sudo install -m 0644 systemd/proxy-monitoring-mcp-oauth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-monitoring-mcp-oauth.service
```

Для первого запуска, когда bearer-службы нет, пропустите её stop/disable.
Коллектор `proxy-monitoring.service` должен оставаться активным. Auth DB находится
в отдельном writable StateDirectory; каталог телеметрии доступен службе только
для чтения. Само приложение также открывает телеметрию read-only.

## Проверка и подключение

```bash
curl -i https://monitor.example.com/mcp
curl -fsS https://monitor.example.com/.well-known/oauth-protected-resource/mcp
curl -fsS https://monitor.example.com/.well-known/oauth-authorization-server
```

Первый запрос должен вернуть 401 и `WWW-Authenticate` с адресом resource metadata.
Два следующих возвращают JSON. Подключайте `https://monitor.example.com/mcp` в
клиенте с OAuth. Клиент регистрируется, открывает страницу входа и после согласия
получает токен. Все 10 инструментов требуют scope `monitor:read`; этот scope даёт
чтение всех источников, включая метки пользователей. `offline_access` разрешает
обновление доступа. Пароль вводится только на вашем HTTPS-домене.

## Сроки, отзыв и эксплуатация

- Код действует 60 секунд, согласие — 5 минут, access token — до 10 минут
- Refresh token действует до 30 дней с первого согласия; обновление не продлевает
  этот абсолютный срок. Каждый refresh одноразовый. Клиент должен сериализовать
  refresh: параллельное использование одного токена отзывает всю авторизацию
- Повторное использование refresh token отзывает все токены этой авторизации.
  Повтор кода с корректными привязками отзывает выданную по нему авторизацию
- `/revoke` принимает form `client_id` и `token`, отзывает всю авторизацию токена.
  Неизвестный token также возвращает 200
- Общие лимиты: 20 регистраций/час, 60 authorize/минуту, 10 попыток входа/5 минут,
  120 token и revoke/минуту. Лимиты сохраняются после рестарта; при превышении 429
- Максимум 1000 зарегистрированных клиентов и 1000 ожидающих согласий. Имена
  клиентов не удостоверены; проверяйте callback на странице согласия

Отозвать все подключения и ожидающие согласия, не трогая сбор данных:

```bash
cd /opt/proxy-monitoring
sudo -u proxy-monitor venv/bin/python -m proxy_monitoring oauth-revoke-all \
  --oauth-config /etc/proxy-monitoring/oauth.json
```

При смене пароля остановите только OAuth-службу, отзовите все подключения, сохраните
старый `owner.hash` вне репозитория, создайте новый через `oauth-init-owner`, установите
владельца/права и запустите службу. Пароль загружается при старте процесса.
Для полного сброса регистраций остановите OAuth-службу и переместите auth DB в
защищённую резервную копию; новый запуск создаст пустую БД, клиенты подключаются заново.
Не восстанавливайте старую auth DB после отзыва: это может вернуть ранее выданный доступ.
Auth DB, hash, production JSON и их резервные копии нельзя включать в Git/релизы.

Транспорт stdio и прежний bearer-режим сохранены. OAuth включается только через
`mcp --transport streamable-http --oauth-config ...`; совмещать его с `--token-file`
или `--public-origin` нельзя. Настройка домена и реальное подключение ChatGPT —
отдельный шаг развёртывания, публикация релиза сама по себе ничего на VM не открывает.
