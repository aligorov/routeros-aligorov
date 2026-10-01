# P0-фиксы по итогам security-аудита (4 патча, один заход)

Область — только непереломные точечные фиксы High-находок. TLS-листенер, дефолт TRUSTED_PROXIES, шифрование секретов в settings, SSRF/DoS-лимиты — ОСОБЫМ планом, не здесь.

## 1. Relay-hub: двойной close(done) → крах сервера (H1)

`internal/api/relay_hub.go`: `relayClient.done` закрывается из четырёх мест (takeover :153, defer readLoop :237, Stop :406, удаление релея admin_relays.go:163) — гонка даёт `panic: close of closed channel` в горутине = падение всего сервиса.

- Единственный владелец закрытия: `sync.Once` на клиенте (`c.closeOnce.Do(func(){ close(c.done) })`) — паттерн уже есть в репо (`bastion.Session.closeOnce`).
- Все четыре места вызывают один метод `c.shutdown()`.
- Тест-регрессия: юнит-тест, дёргающий shutdown из четырёх горутин concurrently (`-race`) — без паники.

## 2. Approve/deny push привязать к владельцу челленджа (H2)

`internal/api/webhooks.go` (`processPushCallback` :183-258) и `internal/telegram/bot.go` (`handleCallback` :375-429): сегодня проверяется только платформа (токен/JWT), не действующий юзер.

- В `processPushCallback` добавить параметр «идентичность отправителя» (канал + id: eXpress `from.user_huid`, TG `from.id`, VK Teams/MAX/Mattermost/VK — соответствующие sender-поля их колбэков; где платформа id не даёт — этот канал помечаем в аудите и оставляем owner-check по доступному идентификатору привязки).
- Резолвить юзера по привязке мессенджера и требовать `resolved == challenge.UserID`; несовпадение → отклонение + аудит `push_approve_denied` (с каналом и идентификатором отправителя, без содержимого).
- TG: `UserByTelegramChat(fromID)` уже есть — сверка одна строка.
- Тесты: колбэк чужого отправителя → 403/отклонение + запись аудита; владелец → approve работает.

## 3. Оракул пароля в логах MSCHAPv2 (H3)

`internal/radiusserver/eapauth.go:1219-1229`: удалить из лог-записи `pwd_sha256`, `pwd_len`, `expected_nt`, `client_nt`, `peer_chal`, `auth_chal`. Оставить user, srcIP, `mschap_name` (уже `%q`). Аудит-строка `radius_fail` уже несёт событие — диагностика не страдает. Тест: после провала inner-MSCHAPv2 в перехваченном лог-выводе нет ни одного из этих полей.

## 4. Backup и settings-export — только под scope 'all' (H4+H5)

- `internal/api/admin_backup.go` (`handleBackup` :193-216) и `internal/api/admin.go` (`handleSettingsExport` :69-81): явная проверка `adminTokenScopeFrom(ctx).allows(ScopeAll)` → иначе 403 `insufficient_scope` (легаси-токен и сессия админа проходят как 'all'). Дополнительный пояс: в дампе/экспорте вычистить `admin_token` по образцу исключения `master_key` (`internal/backup/backup.go:66` — расширить до списка), но scope-гейт — первичный барьер.
- Тесты: токен `settings:read` на `/admin/backup` и `/admin/settings/export` → 403; `all`/легаси → 200; в теле дампа нет `admin_token`.

## Порядок и проверка

1 → 3 (тривиальные) → 4 → 2 (самый объёмный из четырёх). После каждого: `go vet ./... && go test ./internal/api/ ./internal/radiusserver/ ./internal/telegram/` (-race), в конце полный `go test ./...` + `go build -buildvcs=false ./...`. Коммит — раздельный по патчам, явные пути, без тегов/пуша (релиз — ваш). Оценка: ~0.5 дня.

Осознанно НЕ здесь (отдельный план по команде): TLS-листенер, TRUSTED_PROXIES=loopback (ломает деплои за прокси), шифрование секретов settings/master_key из БД, SSRF ×2, body-limits вебхуков/SAML, lockout-DoS, eXpress-привязка по huid.