# FEX64 c9 и FEX32 r5 из открытых исходников

Сценарий предназначен для чистой облачной машины GitHub ARM64 macOS. Он не
разрешает скачивание или исполнение сторонних исходников на Mac владельца.
Публичный fork тоже может вручную запустить этот workflow: секреты не нужны.

1. Клонировать `https://github.com/t0b1kent/hyperbridge.git` на ревизии,
   содержащей этот каталог и `.github/workflows/repro109-fex-c9-macos15-arm64.yml`.
2. Выполнить `python3 -I build/repro109fex/build.py --check-inputs`.
   Проверка офлайн; результат `PLAN_ONLY`, загрузок и сборок 0.
3. В Actions вручную запустить `repro109-fex-c9-macos15-arm64.yml` с пустым
   `only`. Получить артефакт `repro109-fex-c9-<recipe-commit>`.

На облачной машине сам шаг сборки выполняет одну команду:

```sh
python3 -I build/repro109fex/build.py --out "$RUNNER_TEMP/repro109-fex-c9"
```

Для диагностики одной архитектуры добавить `--only fex64` или `--only fex32`;
в workflow это поле `only`. Частичный результат не является полной сборкой.
Предыдущий каталог результата не перезаписывается, повторов автоматически нет.

## Закрепления и точный состав

Все параметры хвоста находятся в `recipe.lock.json`: полная ревизия,
каталог, имя JSON-файла порядка и SHA-256 этого файла. Перенос хвоста при
выпуске меняет закрепление в этом файле; алгоритм сборки не меняется.
Порядок берётся буквально из JSON, сортировки по имени или номеру нет.

- База: hyperbridge `4d489f182db3b05bb7465d9705483c490f718114`, upstream
  FEX `fd141ed6d721d03062619e4702bca1a0c93b6dd9`, опубликованные 55 патчей r5.
- FEX64: публичный хвост `94bc17c974eba1633c1f15fe227a883a765e1fd5`,
  `stands/hardware/candidates/c9-release-defaults-aa-20261007/candidate.json`,
  34 патча. Две продуктовые проверки `X87Region.cpp` и `X87Region.md`,
  отсутствующие в cloud split-context серии, извлекаются из закреплённой
  продуктовой 0162; остальные hunks этого файла повторно не применяются.
- После шести закреплённых submodules, до компиляции: ровно 6928 файлов,
  каждый SHA равен `c9/PRODUCT-MANIFEST.json`; пропуск, лишний файл или
  несовпадение останавливают сборку.
- FEX32: прежняя r5-серия 61 патч (53 общих, шесть WoW64, затем 0160/0161).
  Новый хвост c9 в неё не добавляется. Её собственный source digest проверяется.
- 60 значений окружения берутся из `c9/ENGINE.json` и сверяются с продуктовым
  manifest; четыре умолчания не извлекаются из патчей.

`base/MANIFEST.json` закрепляет 66 исходных входов. В новом packet публикуются
только пять control files и manifest: все 61 файла патчей уже побайтно находятся
в закреплённом открытом repository, путь каждого задан в `public-patches.json`.
Сборщик проверяет SHA каждого перед применением; mailbox headers повторно не
публикуются. Общий сборщик FEX сохранён в `support/build_fex64.py`: добавлены
два явных этапа source callback, lookup всех public patches, лимит числа
заданий и отдельное закрепление ld. Счёт PE: FEX64 содержит две записи
ARM64EC одного уникального DLL; FEX32 содержит 0 EC DLL. Это компонентный
счёт, не полный счёт Wine.

## Машина и инструменты

GitHub `macos-15`, ARM64; Python 3.13.7; Xcode 16.4/16F6; SDK 15.5;
Apple clang 17.0.0; ld 1167.5.0; deployment target 14.0; три задания;
общий бюджет сборщика 330 минут и workflow 360 минут. Xcode выбирается по
точной паре version/build; другой Xcode не подставляется.

LLVM-mingw 20260505, CMake 4.3.2, Ninja 1.13.2 и ccache 4.13.6 закреплены
официальными URL, SHA и размерами в базовых source/tool locks. Архивы и
сторонние исходники загружает только облачный сборщик. Нативный stand builder
закреплён на base revision; все 16 его файлов имеют SHA и размеры. Stand
собирается из c9 FEX64 с проверкой принадлежности compile sources.

## Результат и ограничения

После full compilation выполняется отдельный именованный шаг
`llvm-mingw-libcxxabi-path-canonicalization`. В PE DLL он заменяет ровно
шесть строк `Users/runner` на `build/xxxxxx` той же длины12 только в
read-only `.rdata`. Код и заголовки не меняются; подписанный PE отвергается.
Проверяется SHA256 всего результата до записи:

- FEX64: `ed14b28a89675c4544e84da2a4c271b3cd7c6ac61becbe804aa68cb96553147d`.
- FEX32: `aef436aacd966ce9e55ccc1e68706f4af2d2192da923cf0ae17b682580742025`.

Если весь исходный DLL уже имеет свой release SHA, байты сохраняются
дословно: статус `ALREADY_RELEASE_BYTES`, изменений0. Это необходимо для
принятого FEX32: его reference содержит шесть исходных строк `Users/runner`.
Одинаковая орфография путей у двух архитектур не является критерием;
критерий — точный whole-DLL SHA каждой архитектуры.

Одинаковый DLL нормализуется один раз, затем записываются его проверенные
копии. Исходные DLL и исходный outputs manifest сохраняются в артефакте;
`pe-path-canonicalization.json` содержит все изменённые byte offsets.
Неожиданное число строк, иной итоговый SHA или drift возвращает код1.
Compile-only матрица сохраняет ненормализованные байты для диагностики.
После full producer отдельный workflow step вызывает
`release_bytes.py --verify <out> --only <selector>` и проверяет SHA ещё раз
на границе передачи артефакта; иначе upload сохраняет failed evidence,
а задание остаётся красным. FEX32 reference закреплён, его full cloud
проверка остаётся обязательной.

FEX64 full запуск37567840090 дал DLL5394432Б; после этого именованного шага
он побайтно равен принятому выпуску. Сверены8799/8799 COFF функций;
это не приёмка Unix частей, FEX32, остальных компонентов или стендов.

Артефакт содержит полный bounded журнал сборщика и команд, фактические
версии инструментов, source checks, EC-счёт, FEX64/FEX32 outputs и SHA,
лицензии и исходные notices. `fex-c9-unsigned.tar` содержит компоненты,
лицензии, нативный stand и переносимый ENGINE environment. Рабочие source
trees и tool archives в артефакт не вкладываются.

`install skipped`: активный runtime не заменяется. Подпись и нотаризация
остаются у владельца. Archive — `NOT_GOLDEN`, даже если сборка прошла:
function/section comparison, запуск стендов, app32-gate, композиция Wine,
графики, media и приложения ещё отдельные шаги. Native stand здесь только
собирается, не запускается; это не приёмка FEX32 и не FPS сравнение.

Офлайн-сверка публичных 34 патчей и двух тестовых файлов с сохранённой r5-базой
дала exact 6925/6925 postimages исходного экспорта. Чистая Git-выкачка также
содержит три файла `External/range-v3/.vscode/` из закреплённого submodule
`ca1388fb9da8e69314dda222dc7b139ca84e092f`. Их SHA включены в опись;
проверка всех 6928 файлов сохраняет отказ на missing, extra и changed.
FEX32 использует прежний source digest, без этого FEX64 c9 overlay.
Сверка исходников не доказывает сборку, совместимость
нативного adapter или исполнение готового компонента. Следующая предметная
проверка — full FEX32 и повтор full producer с включённым именованным шагом.

## Матрица шагов FEX64

`repro109-fex-c9-stages-macos15-arm64.yml` сохраняет Xcode16.4/16F6,
SDK15.5 и остальные закрепления текущей облачной сборки. Она запускает
независимые задания с `fail-fast: false`; отказ нативного бегунка не мешает
проверить байты из задания compile. FEX32 full остаётся отдельным контролем.

| `--stage` | Проверяется | Граница |
|---|---|---|
| inventory | Отпечатки входов рецепта, опись6928 и порядок патчей | Actual patched source ещё NOT_ENABLED |
| patches | Реальные pinned checkout, наложение серии, submodules, postimages6928 | CMake configure/build не вызывается |
| configure | Та же подготовка плюс PE/Unix CMake и владение обоими деревьями | Ни один target не компилируется |
| compile | Подготовка, configure, PE/Unix compilation, сохранение5outputs | EC admission и native runner не вызываются |
| native-stand | Подготовка той же серии и её native adapter/runner | PE/Unix target compilation не вызывается |
| admission | Байты из compile того же workflow:5files, SHA/size, Mach-O ARM64, EC2/unique1 | Сборка предшественников не повторяется |

Каждая source-клетка сама выполняет необходимые ей предыдущие шаги;
общая ошибка checkout/patch/tools может поэтому появиться в нескольких
клетках. Inventory проверяет опись, а patches сверяет реальные postimages.
Admission ждёт завершения matrix через `if: always()`, получает compile
artifact по имени с текущим Git SHA. Если compile не вернул outputs,
состояние — `NOT_ENABLED_PREDECESSOR_COMPILE_MISSING`, код1.
Зелёные клетки означают только соответствующие границы, не принятие продукта.

Нативный producer — `support/native-builder.py`, byte-pinned в
`support/native-stand.lock.json`. Это точный snapshot публичного
`stands/synthetic/build.py` с исправлением вывода для sibling build root.
Wrapper задаёт ему ROOT уже проверенного публичного fork4d489f18;
публичные adapter файлы по-прежнему проверяются по исходной описи16.
Так source revision не зависит от ещё не созданного commit исправления.
Native RESULT сохраняет SHA выбранного producer. Для child build root
вывод остаётся относительным, для sibling — абсолютным. Это только
форматирование вывода; source ownership и ARM64 output guards обязательны.

Локальная проверка без загрузок/компилятора:
`REPRO109_TEST_TMP=<свой scratch> python3 -I -B build/repro109fex/test_stages.py`.
Повтор с `-O` проверяет те же отказы; сборка cloud-only.
