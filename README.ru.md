# Хеширование паролей на Oberon

Библиотека хранения паролей для FreeOberon. Реализует SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256, строгий формат записей `oberon-pwh` и определение необходимости обновления хеша.

Текущая поддерживаемая сборка — macOS arm64 с документированной цепочкой FreeOberon/Ofront+. Код прошёл самопроверку с эталонными векторами, тестами мутаций парсера и sanitizer-запусками. Библиотека не является FIPS-validated и не реализует Argon2id, pepper, сессии, rate limiting или TLS; это ответственность приложения.

## Быстрый старт

```sh
export FREEOBERON_HOME=/path/to/FreeOberon
./scripts/test.sh
```

Скрипт собирает проект во временной папке, поэтому сгенерированные C- и symbol-файлы не попадают в исходное дерево. Он умеет работать на macOS arm64/x86_64 и Linux x86_64/aarch64 при наличии соответствующей цели FreeOberon; официально поддерживается пока только macOS arm64.

`PasswordHash.DefaultPolicy` использует 600 000 итераций PBKDF2. Каноническая запись v1 требует `PasswordHash.EncodedCapacity` — 143 байта вместе с завершающим NUL, чего достаточно для всего диапазона знакового 32-битного числа итераций v1.

Для дополнительной проверки безопасности памяти:

```sh
CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' ./scripts/test.sh
```

Документация: [English README](README.md) · [Русские требования](docs/requirements.ru.md) · [сборка](docs/build.ru.md) · [переносимость](docs/portability.ru.md) · [поддержка и безопасность](docs/support.ru.md)
