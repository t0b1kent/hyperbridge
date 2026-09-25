#!/bin/sh
# MacRunner 2026-08-17, лейн ЛЕСТНИЦА — СБОРКА СРАВНИВАЮЩЕГО СТЕНДА (итерация 1530).
#
# Зачем файл. Правила для `hb_diff_case_runner` в `engine/hyperbridge/Makefile` НЕТ. Двоичный
# собирался явной командой, которая жила только в истории команд сессии. 17.08 я удалил
# двоичный (пытаясь обойти то, что `make` возвращает 0 и ничего не делает), сборка упала, и
# восстановить стенд удалось лишь подбором — команды нигде не было записано.
#
# ДВЕ ЛОВУШКИ, обе стоили попыток:
#
# 1. `make -C engine/hyperbridge tests/hb_diff_case_runner` возвращает 0 и НЕ пересобирает,
#    когда изменена только `libhyperbridge.a`. Удалять цель перед сборкой бесполезно —
#    правила нет, и сборка просто падает с неразрешёнными символами.
# 2. `clang` из `PATH` — это кросс-набор llvm-mingw (`engine/toolchain/…`), у него НЕТ
#    заголовков macOS: сборка умирает на `#include <ctype.h>`. Нужен `xcrun clang`.
#
# Библиотеку пересобирать ОТДЕЛЬНО и ДО этого скрипта:
#     make -C engine/hyperbridge -j8 libhyperbridge.a
# ★ ИМЕНА ПЕРЕМЕННЫХ ТОЛЬКО ЛАТИНИЦЕЙ (итерация 1530). Первая редакция этого файла
# использовала `КОРЕНЬ` и `ХБ` — `/bin/sh` кириллицу идентификатором не считает и упал на
# `КОРЕНЬ=...: No such file or directory`. Это записанная ловушка лейна (та же в
# `run_recorded.sh`), и я шагнул в неё, имея её же в комментарии соседнего файла.
set -e
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HB="$ROOT/engine/hyperbridge"
xcrun clang -O2 -std=c11 -I "$HB/include" -arch arm64 -mmacosx-version-min=14.0 \
    "$HB/tests/hb_diff_case_runner.c" "$HB/libhyperbridge.a" \
    -o "$HB/tests/hb_diff_case_runner"
echo "собран: $HB/tests/hb_diff_case_runner"
echo "проверка: $HB/tests/hb_diff_case_runner < $ROOT/tools/lestnica/regress-cases.txt"
echo "ожидание: 38 случаев, расхождений 0, отказов сторожа 0"
