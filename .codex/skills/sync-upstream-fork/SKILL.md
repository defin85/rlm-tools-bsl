---
name: sync-upstream-fork
description: Безопасно переносит свежие изменения Dach-Coin/rlm-tools-bsl из upstream/master в опубликованное ответвление с поддержкой v8unpack. Использовать при запросах обновить fork, подтянуть upstream, выполнить пробное слияние, разобрать конфликты upstream или проверить совместимость ответвления после нового релиза.
---

# Синхронизация ответвления с upstream

Переносить upstream обычным merge-коммитом. Не переписывать опубликованную
историю ответвления через rebase и не применять `ours`/`theirs` ко всему
дереву.

## 1. Проверить исходное состояние

Работать только из корня этого репозитория.

```bash
git status --short --branch
git remote -v
git fetch upstream master
git rev-list --left-right --count upstream/master...master
```

Остановиться при незакоммиченных пользовательских изменениях. Не выполнять
слияние поверх них. Не отправлять изменения на сервер без явного запроса.

## 2. Создать ветку синхронизации

Сначала обновить локальный `master` только быстрым переходом, затем создать
датированную ветку:

```bash
git switch master
git pull --ff-only origin master
git switch -c sync/upstream-YYYYMMDD
git merge --no-ff upstream/master
```

Если конфликтов нет, всё равно проверить итоговое отличие и инварианты
ответвления.

## 3. Разрешить конфликты

Считать код upstream новой основой и возвращать поверх него только необходимые
добавления ответвления. Не выбирать целиком сторону файла, если обе стороны
меняли поведение.

Сохранять следующие инварианты:

- `v8unpack` остаётся поддерживаемым `SourceFormat`, а не неизвестным форматом;
- JSON-метаданные и формы `v8unpack` сохраняют явные состояния
  `complete`/`partial`/`unsupported`/`failed`;
- `BUILDER_VERSION` не уменьшается и остаётся уникальным для фактической схемы;
- версия пакета наследует свежую версию upstream и получает локальную метку,
  например `1.30.1+v8unpack.1`;
- документация upstream сохраняется вместе с дополнениями `v8unpack`;
- отличающаяся семантика `git_search` сверяется с реальным кодом и проверками,
  а не выбирается по тексту одной стороны.

Ожидаемые горячие точки:

- `bsl_index.py`, `format_detector.py`, `server.py` — встраивать крючки
  `v8unpack` в новую структуру upstream;
- `bsl_helpers.py` — принимать исправления upstream и проверять наши отличия
  отдельными тестами;
- `CHANGELOG.md`, `docs/HELPERS.md`, `docs/INDEXING.md`,
  `docs/MODULE_MAP.md` — объединять смысл вручную;
- `pyproject.toml` — взять зависимости upstream и назначить локальную версию;
- `uv.lock` — после разрешения `pyproject.toml` взять upstream как основу и
  пересоздать командой `uv lock`.

После разрешения убедиться, что маркеров не осталось:

```bash
rg -n '^(<<<<<<<|=======|>>>>>>>)' .
git diff --check
git status --short
```

## 4. Проверить результат

Сначала выполнить быстрые проверки пересечённых подсистем:

```bash
uv run ruff check .
uv run pytest -q \
  tests/test_arg_guards.py \
  tests/test_bsl_helpers.py \
  tests/test_extension_overrides.py \
  tests/test_help_recipes.py \
  tests/test_search_extension.py \
  tests/test_start_cost_budget.py \
  tests/test_strategy_data.py \
  tests/test_v8unpack_support.py \
  tests/test_v8unpack_metadata_codec.py \
  tests/test_v8unpack_forms.py
```

Затем выполнить полный прогон:

```bash
mkdir -p /var/tmp/rlm-tools-bsl-tests
TMPDIR=/var/tmp/rlm-tools-bsl-tests uv run pytest -q
git diff --check master...HEAD
```

Изолированный `TMPDIR` обязателен: проверки `extension_detector` ищут соседние
конфигурации, поэтому посторонняя выгрузка в общем `/tmp` даёт ложный
`nearby_main`. Не удалять чужие временные выгрузки ради зелёного прогона.

Если менялись построитель или формат источников, дополнительно выполнить чистую
сборку эталонного индекса `v8unpack` и проверить опубликованные счётчики
полноты. Исправленный исходный код без этой проверки не доказывает работу
живого индекса.

## 5. Зафиксировать и принять слияние

Создать отдельный merge-коммит с номером принятого релиза upstream:

```bash
git commit -m "merge: sync upstream vX.Y.Z"
```

После всех проверок быстро передвинуть `master` на проверенный результат:

```bash
git switch master
git merge --ff-only sync/upstream-YYYYMMDD
```

Не удалять ветку синхронизации и не выполнять `git push`, пока пользователь
явно этого не запросил. В отчёте указать:

- исходный и принятый SHA upstream;
- список конфликтов и решения по ним;
- локальную версию пакета и `BUILDER_VERSION`;
- команды проверок и точные результаты;
- SHA merge-коммита и состояние `master`.
