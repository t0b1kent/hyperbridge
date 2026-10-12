# Проверка поставки v5

Дата: 12.10.2026. Проверялось в Linux, **без исполнения PE и без Wine**.

## Подтверждено

- Полная C11 translation unit собрана и скомпонована настоящим llvm-mingw `20260505-ucrt-ubuntu-22.04-x86_64`, clang **22.1.5**, target `x86_64-w64-windows-gnu`, с реальными публичными Windows headers/import libraries.
- Основная конфигурация: `-std=c11 -fms-extensions -O1 -g -Wall -Wextra -Werror -municode`.
- Дополнительные O0 и O2 compile/link также прошли без предупреждений; это compile/static-only проверки.
- Clang static analyzer для окончательного C исходника завершился без диагностик. Проверены и исправлены cleanup-пути адреса собственной стековой переменной.
- `check_static.py` прошёл для O0/O1/O2: восемь функций, девять точных однобайтных PUSHFQ в каждой, точные CD 2D/CC, первые 16 MOV-снимков, независимый marker выполненного capture path, совпадающие 125-байтные прологи и unwind layout, настоящий `__C_specific_handler` именно у `invoke`, сохранённая рекурсия depth-control.
- Независимый просмотр подтвердил inherited-frame alternate landing, первый образ PUSHFQ до TF safety-clear, контроль безопасных границ и отсутствие переходов по неизвестной длине в DLL.
- Генератор `generate_asm.py` воспроизводит включённый `asm_fragment.h` побайтно.
- 67 тестов checker прошли в обычном Python и с `python -O`. Среди них три статических теста соответствия фактических C-emitter полей/enum/schema синтетическим fixtures. Эти тесты не исполняют emitter под Windows и не создают Windows-эталон.
- Python-файлы прошли `py_compile`.

## Не подтверждено

- Native Windows 2022/2025 доставка, продолжение, TF, VCH и API **не исполнялись**.
- PowerShell отсутствует в проверяющей среде. Runner прочитан независимо, но PowerShell parse/runtime здесь не проверен.
- Настоящих `raw.jsonl` / Windows summary нет. Синтетические fixtures существуют только внутри unit-тестов и не поставляются как замеры.
- Поведение HyperBridge/FEX/Wine этим пакетом не проверялось; их код не менялся.
- Сырьё v4 ещё не предоставлено, поэтому часть 5 ожидает его и не обозначена выполненной.

## Воспроизведение

```text
python -m unittest -v test_checker.py
python -O -m unittest -v test_checker.py
python check_static.py YOUR_OWN_PROBE.exe --tool-dir LLVM_MINGW_BIN
```

Статическая проверка касается только собственного созданного PE. Никакие исполняемые файлы, объектные файлы, дампы, toolchain или результаты выдуманного native run в source-only архив не включены. SHA256SUMS покрывает все остальные файлы пакета; сам SHA256SUMS не хеширует себя. SHA-256 ZIP сообщается отдельно.
