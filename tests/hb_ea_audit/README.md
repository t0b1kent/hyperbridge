# HyperBridge: аудит EA при живых регистрах

Этот тест компилирует **настоящий `src/hb_arm64_codegen.c`**, получает выпущенные
AArch64-слова и проверяет их ограниченным оценщиком. Эталон значений и вычисления
адреса — нативные инструкции x86/SSE2/SSE4.1. Это **не** запуск ARM-кода на Mac
и **не** семантический тест всех runtime-helper'ов.

## Запуск

Нужен Linux x86-64, Python 3, clang, libc development headers и SSE4.1.
Python-зависимостей из PyPI нет. Запуск из корня HyperBridge:

```bash
python3 tests/hb_ea_audit/run_suite.py --require-clean
```

`0` — в выполненном корпусе нет расхождений; `1` — есть fault/mismatch/unsupported;
`2` — ошибка сборки или самого стенда. Итоги: `tests/hb_ea_audit/out/summary.json`.

Полный отрицательный контроль на коммите до девяти правок, но **после** фикса XMM:

```bash
mkdir -p tests/hb_ea_audit/out
git show 748d62458dde911e226e407ce43bf6c50cefd12d:src/hb_arm64_codegen.c > tests/hb_ea_audit/out/baseline-codegen.c
python3 tests/hb_ea_audit/run_suite.py \
  --source tests/hb_ea_audit/out/baseline-codegen.c \
  --out tests/hb_ea_audit/out/before \
  --require-clean
```

Ожидаемый код выхода последней команды — **1**. `--source` меняет именно исходник
эмиттера; эталон, входы и тесты остаются теми же.

Проверка **каждой** правки на соседних стадиях серии. Архив результатов должен
быть распакован в `$HOME/Downloads/hb-memory-live-audit`:

```bash
python3 tests/hb_ea_audit/check_regressions.py \
  --repo "$PWD" \
  --baseline "$HOME/Downloads/hb-memory-live-audit/snapshots/head-codegen.c" \
  --patch-dir "$HOME/Downloads/hb-memory-live-audit/patches" \
  --out tests/hb_ea_audit/out/negative-controls.json
```

Ожидаются девять строк F01–F09: `fault -> pass`, кроме F07: `mismatch -> pass`.
Стенд требует именно девять нумерованных патчей; порядок важен.

## Корпус

32 формы адреса для x64: base с disp 0/±4095/±4096; полное произведение
index scale 1/2/4/8 × те же пять disp; три абсолютных адреса после лифтера;
четыре no-base indexed формы. Для i386 абсолютные значения больше 32 бит
исключены. Пограничные i386-входы: base=0xfffffff0, index=0x10.

10 конфигураций: x64 framed/lean и i386 framed/lean × pinned/unpinned × fused/off.
При unpinned+fused проверяется реальная деградация к материализованному пути.

Включены скалярные читатели операндов, CMP/TEST/Jcc, нативные RMW ADD/SUB/AND/OR/XOR,
LSE LOCK ADD/SUB/AND/OR/XOR, пары и adjacent mem64, XMM load/store и логика,
PUNPCK, INSERTPS (все 256 register-immediate), EXTRACTPS (все 4 register-selectors),
stack/branch/extend/scan/copy/fill. Register-only ADD/SUB/AND/OR/XOR — контрольные
входы: проверяемый scalar-result emitter не принимает memory arithmetic.
Входы RMW ADC/SBB, которые native emitter отвергает, учитываются как declined.

CMPXCHG, CMPXCHG8B/16B, представительные x87 FLD/FADD/FSTP, memory INSERTPS/EXTRACTPS,
VEX128/AVX256 XOR проходят отдельную проверку dispatch/helper ABI.
Это **не** полный value-тест этих семейств и не исчерпывающий список x87/AVX opcode.
CMPXCHG16B не подаётся в i386; memory INSERTPS/EXTRACTPS имеют размер 4 байта.

## Что именно проверяется

- Значения регистров/памяти и адреса по нативному x86 oracle.
- Контрольные байты вокруг областей основного корпуса, сохранность pinned X24.
- Сложные формы адреса при живых operand/loop-регистрах; lean remap.
- Выбранные условия Jcc сравниваются с флагами нативного x86.
- Все неизвестные A64-слова дают `unsupported`, а не успешный результат.

`helper-route` проверяет только семейство helper, указатель контекста и IR-аргумент.
`production-reemits-with-frame` означает, что lean-проба выпускает вызов:
реальный блоковый компилятор переэмитирует такую ветвь с frame. Эти случаи **не**
включены в `pass`. `declined` — отказ конкретного leaf emitter, также не `pass`.

Три transfer-helper ABI моделируются ограниченно: load-to-GPR, scalar store,
u128 store. C-helper'ы интерпретатора/атомиков не исполняются. Проверка LSE
однопоточная, без доказательства атомарности, ordering, alignment faults или
сигналов. Отложенные флаги RMW проверяются не полностью. Нет полного
регистрового alias-product, FS/GS/segment/permission/SMC-покрытия, запуска
лифтера для каждого opcode, пролога/эпилога полного runtime или Wine-адаптера.

Фиксированный seed: 20260926. Данные и варианты записываются в `main.json`;
фактический машинный код, register map и helper-адреса — в `main.code.json`.
То же для дополнительного корпуса: `extra.json` и `extra.code.json`.

## Контрольные результаты 26.09.2026

На исходнике `748d624`: pass 70400, fault 17118, mismatch 110.
После девяти правок: pass **87628**, fault/mismatch/unsupported **0**.
Отдельно и неизменно: declined 10962, helper-route 1736, reemit-with-frame 4408.
Всего 104734 записи; 57200 эмиссий на версию исходника. Числа относятся
к этому ограниченному корпусу, а не к общему `make test` проекта.
