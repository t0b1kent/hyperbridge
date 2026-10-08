ДЛЯ КУРАТОРА: пакет по поручению 08.10 11:06 для отдельной ветки
repro109/llvm22-q-restores-20261008 открытого hyperbridge. Narrow push этой
описи запускает четыре клетки; workflow_dispatch не требует регистрации на main
для первого запуска. Лейн не отправляет и не запускает задачу.

Матрица fail-fast:false: patch / build / level4-test / synthetic-asm.
Каждая клетка независима и получает официальный llvmorg-22.1.5 source archive
только в cloud, с точными 167058820 Б / SHA7972b87b… из lock. Перед извлечением
— прежний собственный archive validator; base/patched SHA шести файлов LEVEL4
проверяются до/после git apply. Патч11071Б/SHAbe727326… иsynthetic MIT input
перенесены без изменения, default:false сохранён.

Переиспользован source/root/static-CMake/cache ownership подход принятого
рецепта DXMT run37567821557 (f804f27c, build/repro109dxmt/build_llvm15.py).
Различия явные: LLVM22 вместо15.0.7, Linux x86-64/GCC13 вместоDarwin,
LLVM_TARGETS_TO_BUILD=AArch64, LLVM_ENABLE_PROJECTS=clang; AIR/libunwind не нужны.
Собираются llc+clang и малые FileCheck/llvm-readobj для полного теста.
Все17 RUN строки LEVEL4 выполняются по порядку, включая FileCheck, unwind,
entry/exit siblings, disabled thunk generation и обычный AArch64 control.
Skip/нулевой testcount успехом не считается. Три клетки скомпиляцией делают
свои независимые сборки; артефакт проваленной клетки не отменяет остальные.

Runnerubuntu-24.04, Python3.13.7, GCC13/g++13; фактические host tool versions
полностью сохраняются. CMake/Ninja patch versions ещё не квалифицированы как
неизменный toolchain для BUILD.md продукта: это boundedDIAGNOSTIC_ONLY/NOT_GOLDEN.
До download нужны ≥10ГиБ free disk и≥6ГиБ available RAM; compile2/link1.
Потолки75минproducer/90минjob, один command≤60мин; actualruntimeNOT_MEASURED.
Первая границаhost/platform/tool/capacity, следующая official SHA иpatch preimages.

synthetic-asm порождает REAL .s исправленным clang: before — defaultoff,
after — только -mllvm -aarch64-arm64ec-split-thunk-q-restores=true.
Третья .s explicit-off с =false должна byte-exact совпасть с default before.
Q-LOAD-COUNTS.json содержит точные ldpq/ldrq/stpq отдельно для каждого
$ientry_thunk$ в границах .seh_proc/.seh_endproc, строки, SHA тела и число
команд; native/exit/comments не включены. Общие счётчики файла сохранены отдельно.
Для каждой entry проверяются 5/0/5 → 0/10/5; несовпадение — FAILED с сырыми .s.
Отсутствующий entry — отказ, не нулевой счёт. Assertions включены. Все три .s — artifact.
Ожидаемый/переписанный assembler не подставляется. RESULT/calls/raw/CMakeCache/
compile_commands/tools/license сохраняются и при отказе. Log cap64МиБ наcommand,
это порог остановки: polling100мс может сохранить overshoot, его точные
bytes/SHA записываются. Переполнение —DROPPED/scopedstop, неPASS; raw0 —EMPTY.
Actions artifacts хранятся7дней, release не создаётся, contents:read.

Офлайн из клона, без source downloads/compiler:
`REPRO109_TEST_SCRATCH=<new-normal-dir> python3 -I -B build/repro109llvm22/test_run.py`;
повтор с -O иДРУГИМscratch. На Маке только эти собственные controls;
run.py cloudgate отказывает до файлов/сети/чужого кода.

Это Linux host tools для codegen probe, не Wine toolchain и не продуктовый
runtime. Полный compiler для пересборки Wine — отдельный следующий пакет
ТОЛЬКО после зелёных четырёх клеток. Games/Winert/sign/notarization/install0.
