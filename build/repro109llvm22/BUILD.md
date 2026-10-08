ДЛЯ КУРАТОРА: проверки готовой сборкой run37736522794 по поручению 08.10 17:32,
поверх d3466bfc484a5cebed042dc0c6a727e85a3cb243 в ветке
repro109/llvm22-q-restores-20261008 открытого hyperbridge. Эта опись отключает
push-триггер прежней полной матрицы. Узкая выкладка куратора в эту ветку запускает
только repro109-llvm22-q-reuse.yml: две клетки level4-test/synthetic-asm, actions:read,
закреплённый download-artifact с run-id37736522794. Лейн ничего не отправляет.

Первый запуск нового workflow — branch push куратора: dispatch-only требует
регистрации workflow на default branch по документации GitHub. После первого
запуска manual dispatch доступен через API/CLI; вынос в main не нужен для этой
проверки. Прежняя полная матрица по push не запускается.

REUSE-BUILD.json закрепляет actual tar116047837Б, SHA256
872ecde61f1042988b912008073cd9f3821a7cb79f5c73e6b0d9f12cff3a5302.
BuildRESULT602bcb0f…/SHAREDafbf9368… подтвердили успешную общую сборку.
Архив хранится7дней; при потере артефакта задача отказывает без fallback/rebuild.
Frozen producer-d3466bf/run.py сначала проверяет старый export по своему lock,
затем reuse.py готовит новые6IR и зовёт прежний run_checks с теми же4tools.
Для LEVEL4 только в облаке скачивается официальный pinnedLLVMarchive из lock:
копируются ровно arm64ec-entry-thunks.ll/arm64ec-exit-thunks.ll с SHA иразмерами.
Сама сборка LLVM в reuse не вызывается. SHARED-SUPPORT-INPUTS иTEST-ORDER-FIX
включены; исправленный arm64ec-split-q-restores.ll проверяется по новой описи.
Оригинальный full workflow ниже остаётся для будущей отдельной полной сборки.

Четыре границы: patch / build / level4-test / synthetic-asm. Первый job:
матрица patch/build, fail-fast:false. Только эти две клетки получают официальный
llvmorg-22.1.5 archive в cloud, с точными167058820Б/SHA7972b87b… из lock. Перед извлечением
— прежний собственный archive validator; base/patched SHA шести файлов LEVEL4
проверяются до/после git apply. Патч11071Б/SHAbe727326… иsynthetic MIT input
перенесены без изменения, default:false сохранён.

Переиспользован source/root/static-CMake/cache ownership подход принятого
рецепта DXMT run37567821557 (f804f27c, build/repro109dxmt/build_llvm15.py).
Различия явные: LLVM22 вместо15.0.7, Linux x86-64/GCC13 вместоDarwin,
LLVM_TARGETS_TO_BUILD=AArch64, LLVM_ENABLE_PROJECTS=clang; AIR/libunwind не нужны.
Собираются llc+clang и малые FileCheck/llvm-readobj для полного теста.
Все17 RUN строки исходного LEVEL4 выполняются по порядку, включая FileCheck, unwind,
entry/exit siblings, disabled thunk generation и обычный AArch64 control.
Skip/нулевой testcount успехом не считается. Компиляция РОВНО ОДНА — в build.
После успешного первого job второй job запускает матрицу level4-test/synthetic-asm,
fail-fast:false; оба получают build artifact ЭТОГО run через закреплённый
actions/download-artifact. При отказе build эти проверки NOT_ENABLED/skipped,
не PASS. Никакого fallback к скачиванию LLVM или повторной компиляции.
SHARED-BUILD.json связывает tools, patched test, license и recipe/source hashes
с repository/revision/run_id. До исполнения: SHA tar и всех выбранных файлов,
успешный RESULT build, exact tool set, executable modes, ELF64 x86-64,
source/patch/lock pins и точные SHA всех четырёх тестов; caps1000members/2GiB,
без symlinks/hardlinks/traversal/duplicates. Sidecar должен называть выбранный tar.

Runnerubuntu-24.04, Python3.13.7, GCC13/g++13; фактические host tool versions
полностью сохраняются. CMake/Ninja patch versions ещё не квалифицированы как
неизменный toolchain для BUILD.md продукта: это boundedDIAGNOSTIC_ONLY/NOT_GOLDEN.
Для source/build нужны≥10ГиБ free disk и≥10ГиБ available RAM; compile4/link1.
Потолки180минproducer/200минjob; build command150мин вместо прежних60,
остальные команды60мин. Проверки:20минproducer/30минjob. Timeout команды
ограничивается также оставшимся общим deadline и записывается в RESULT.
Прошлый run37717057447: patchSUCCESS, три компиляции FAILED_TIMEOUT60мин;
этот факт не доказывает ни корректность, ни ошибку ещё не собранного compiler.
Повтор37736522794 завершён: patch/buildSUCCESS, synthetic-asmPASS_BOUNDARY,
level4-testFAILED наRUN08 (нетsupportIR); RUN00–07PASS. Эти receipts не означают
прохождение нового полногоLEVEL4. Облачный reuse ещёNOT_ENABLED.
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
`REPRO109_TEST_SCRATCH=<new-normal-dir> python3 -I -B -m unittest discover -s build/repro109llvm22 -p 'test_*.py'`;
повтор с -O иДРУГИМscratch. На Маке только эти собственные controls;
run.py cloudgate отказывает до файлов/сети/чужого кода.

Это Linux host tools для codegen probe, не Wine toolchain и не продуктовый
runtime. Полный compiler для пересборки Wine — отдельный следующий пакет
ТОЛЬКО после зелёных четырёх клеток. Games/Winert/sign/notarization/install0.

Дополнение LEVEL4 08.10 03:56:40UTC: три собственных IR-входа перенесены
побайтно, 6+9+12 RUN строк, вместе с исходным 17 = 44. EXTRA-TESTS.json
закрепляет байты, SHA и число команд; lock закрепляет SHA самой описи.
Патч и SOURCE-MANIFEST.json НЕ изменены. После git apply новые имена должны
отсутствовать в upstream, только затем они копируются в CodeGen/AArch64.
Shared artifact содержит все четыре IR и их SHA; пропуск/замена/дубликат
отказывает до исполнения. Один и тот же llc/FileCheck/llvm-readobj выполняет
все 44 команды; отдельные временные файлы и полные журналы для каждого IR.
Используется прежний исполнитель точных RUN-команд с %s/%S/%t и pipefail;
llvm-lit не запускается, LLVM build/test config не переносится между машинами.
Тесты покрывают frame192/offset16, frame256/add-SP, default=false и неизменные
ordinary Windows/ELF функции. После первого отказа сохраняются достигнутые
счётчики по каждому входу; 44 подготовленные команды ещё не 44 PASS LLVM.

Reuse RUN 10: явный stdout (исправление тестового рецепта)

В reuse 37768658862 на 2b1df35848722b9ee292f8e1f4c7b6d5af2fe86c
primary RUN 00–09 прошли, RUN 10 отказал: FileCheck получил пустой stdin.
Команда передавала llc имя arm64ec-exit-thunks.ll без -o. По
[официальной документации LLVM](https://releases.llvm.org/22.1.0/docs/CommandGuide/llc.html)
в этом случае ассемблерный вывод записывается в файл, а не в stdout.
TEST-ORDER-FIX меняет другой дополнительный IR и не исправляет этот RUN.

reuse.py исправляет ровно один RUN рабочей копии primary: добавляет -o -.
До записи проверяются точные исходные 4553 байта/SHA
20b1bc0303630146d935ab0f4c5c0fa0075aaa65b09a981b26cb9b664db32a30,
после — 4558 байт/SHA
6662a8e180386ad1546e153601ef5941d09e17c84c6b7e07ee2ee47cd8685820.
В RESULT записывается primary_test_run_adjustment с обоими отпечатками и RUN;
артефакт сохраняет primary.producer.ll и исправленный primary .ll.
Оригинальный producer test, LLVM patch, lock и четыре инструмента не меняются;
все 44 RUN остаются обязательными. Результат в облаке ещё не получен.
При подготовке следующего полного компилятора нужно перенести эту же явную
правку тестового рецепта; текущая правка применяется только в reuse.
