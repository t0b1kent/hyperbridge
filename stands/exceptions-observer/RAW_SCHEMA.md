# raw.jsonl и summary.json

## Общий формат

`raw.jsonl` — UTF-8, одна JSON object на завершённую строку. Порядок полей внутри объекта незначим; одинаковые имена полей в одном объекте запрещены. Пустые строки, повреждённый JSON и обычные JSON numbers — ошибки checker.

Все числовые значения представлены строками с префиксом `0x`, без обязательной фиксированной ширины: `"0x0"`, `"0x13"`, `"0x80000003"`. Только относительные `RipOffset` и `ExceptionAddressOffset` могут быть отрицательными: `"-0x10"`. `true`, `false` и `null` остаются JSON boolean/null. Имена вариантов, статусы и поясняющие текстовые поля — обычные строки, даже если содержат цифры.

Поля с суффиксом `bytes_hex` и `context.xmm.XmmN` — побайтовые дампы в порядке памяти, а не текстовая запись одного числа, полученная обращением порядка байтов. Один байт кодируется двумя hex-цифрами; начальный `0x` сохраняется. XMM содержит ровно 16 байт. Адреса и числовые регистры, напротив, печатаются как значения целых чисел.

Версия схемы: `manifest.schema_version = "0x1"`. В штатном файле одного родительского запуска ровно один manifest, семь thread-context записей, `thread_cleanup`, `thread_block_result`, затем записи 216 групп. Сбой раннего запуска может оставить эти записи отсутствующими; checker покажет неполноту. Число `observation` не фиксировано: одна запись на **одну доставку**, а не одна на повтор. На каждый из 4320 ключей нужен терминальный `run_result`, даже если родитель вынужден явно отметить аварийно не начатый повтор.

## Ключ одного повтора

`run_start`, `observation` и `run_result` содержат объект `key` с ровно следующими полями:

| Поле | Допустимые значения |
|---|---|
| `variant` | `int3_cc`, `int3_cd03`, `int2d_0`, `int2d_1`, `int2d_2`, `int2d_3`, `int2d_4`, `int2d_5`, `int2d_10`, `icebp`, `debugbreak`, `raise0`, `raise1`, `single_step`, `ud2`, `int2c`, `hlt`, `int1_cd01` |
| `observer` | `veh`, `seh`, `uef` |
| `flag_seed` | `clear`, `set` |
| `policy` | `advance`, `keep_then_advance` |
| `repeat` | `"0x0"`…`"0x13"` включительно |

`clear` соответствует арифметической маске `0x0`, `set` — `0x8d5`; полный EFLAGS этим полем не задан. Ключ группы имеет первые четыре поля без `repeat`.

## type = manifest

Описание запланированного измерения и сборки:

- `schema_version`, `planned_runs`, `families`, `variants`, `observers`, `flag_seeds`, `policies`, `repeats`, `groups`: числовая спецификация закрытой матрицы, все в hex-строках.
- `group_timeout_ms`: максимальное основное ожидание одного собственного дочернего процесса.
- `context_size`: `sizeof(CONTEXT)` данной x64-сборки; это **не размер XSTATE**.
- `architecture`: `x86_64`; `compiler`: строка версии Clang.
- `runtime_claim`: пояснение, что файл содержит наблюдения без подставленных ожидаемых значений Windows.
- `raw_numbers`, `xstate_total_length`: описание формата и ограничения extended context.
- `native_processor_architecture`: значение `GetNativeSystemInfo` в родителе.

Сведения PowerShell об ОС, архитектуре и компиляторе также находятся в отдельных `run_environment.json` и `build/*.log`; они не заменяют записи измерений.

## type = run_start

Предшествует попытке выполнить повтор:

- `key`
- `stack_depth`: дополнительная глубина рекурсии, равна номеру повтора.
- `process_id`: PID конкретного собственного дочернего процесса. Все 20 повторов одной группы должны относиться к одному ребёнку.
- `arithmetic_flags_mask`: `"0x8d5"`.
- `requested_arithmetic_flags`: `"0x0"` либо `"0x8d5"`.
- `instruction_site`, `sled_start`: абсолютные собственные метки.
- `family`: номер исходной клетки 1…12 как hex-строка.
- `stack_pattern`: пояснение предыстории собственного зарезервированного окна. Точное исключение для верхних восьми байт после POPFQ описано в DESIGN.md.

При запуске, прерванном до этого повтора, родитель может дать `run_result: runtime_aborted` без `run_start`. Это явная неполнота измерения, не пропущенная строка, замаскированная под старт.

## type = observation

`key` и `delivery_index` идентифицируют доставку. Индексы непрерывны от `"0x1"`; максимум `"0x5"`, последний доступен для жёсткой защиты аппаратной клетки. Никакое ожидаемое число доставок заранее не навязывается.

### exception

| Поле | Значение |
|---|---|
| `ExceptionCode`, `ExceptionFlags` | Исходные DWORD из EXCEPTION_RECORD |
| `ExceptionAddress` | Абсолютный исходный адрес |
| `ExceptionAddressOffset` | Знаковая разность ExceptionAddress − instruction_site |
| `NumberParameters` | Исходное число параметров |
| `ExceptionInformation` | Ровно четыре hex-строки: исходные слоты 0…3 |

При `NumberParameters < 4` слоты за границей числа параметров сохраняются как сырые байты поля структуры; это не действительные аргументы исключения и не обязательные нули.

### context

Исходный `CONTEXT`, взятый до мутаций:

- `ContextFlags`, `Rip`, `RipOffset`, `EFlags`, `Rsp`, `RspMod16`.
- `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr6`, `Dr7`.
- `SegCs`, `SegDs`, `SegEs`, `SegFs`, `SegGs`, `SegSs`, `MxCsr`.
- `P1Home`, `P2Home`, `P3Home`, `P4Home`, `P5Home`, `P6Home`.
- `DebugControl`, `LastBranchToRip`, `LastBranchFromRip`, `LastExceptionToRip`, `LastExceptionFromRip`.
- `gpr`: `Rax`, `Rcx`, `Rdx`, `Rbx`, `Rsp`, `Rbp`, `Rsi`, `Rdi`, `R8`…`R15`.
- `xmm`: `Xmm0`…`Xmm15`, каждый в виде 16 байт в порядке памяти.

`RipOffset = Rip − instruction_site`; `RspMod16 = Rsp & 0xf`. Поля из невыбранных разделов `ContextFlags` сохраняются без обещания валидности.

### Снимок и сравнение с предысторией

- `context_bytes_hex`: все байты фиксированной копии CONTEXT; без чтения соседнего extended context.
- `context_size`: длина именно этой фиксированной копии.
- `context_field_semantics`: `raw_bytes_validity_depends_on_returned_ContextFlags`.
- `exception_information_valid_slots`: минимум из NumberParameters и 4, как hex-строка.
- `gpr_expected`: ожидаемый набор перед инструкцией/вызовом. RBP/RSP здесь runtime-значения; API аргументы и RAX INT 2D уже учтены.
- `gpr_differences`: имена GPR, чьи значения снимка не равны соответствующему `gpr_expected`.
- `xmm_differences`: имена XMM, не совпавших с константами `probe_xmm_seed`.
- `register_interpretation`: `instruction_entry_seed_comparison` или `api_pre_call_differences_not_preservation_failures`.

Пустой список различий — совпадение с предысторией, а не гарантия валидности всех разделов. Непустой список сам по себе не является ошибкой Windows или сравниваемой реализации.

### xstate

- `present`: буквально `(ContextFlags & 0x40) != 0`.
- `total_length`: `null` в этой реализации.
- `length_status`: `unavailable_documented_size_for_borrowed_context`.

Булево `present` говорит о флаге, не о проверенном формате произвольной памяти за CONTEXT. Даже если бит не установлен, нулевая длина не придумывается.

### continuation

- `requested_policy`: совпадает с `key.policy`.
- `action`: фактическое решение `keep`, `advance`, `keep_fallback`, `escape` или `terminate`.
- `proposed_rip`: абсолютная цель **запрошенной** политики, либо `null`, если нельзя вычислить длину/API-прибавление.
- `actual_rip`: абсолютный RIP, передаваемый обратно ОС, либо `null`, если продолжения нет и процесс завершается.
- `tf_cleared`: входящий TF был установлен и после снимка очищен для безопасности.
- `reason`: машинно-читаемая причина решения.

Типовые причины: `requested_policy`, `api_instruction_length_unavailable`, `requested_destination_not_owned_instruction_boundary`, `total_delivery_guard`, `api_repeat_guard_no_documented_instruction_length`, `noncontinuable_exception`, `owned_cleanup_frame_not_verified`.

Для escape `proposed_rip` не затирается удобной меткой cleanup: запрошенная и фактическая цели различаются явно. Байтовые данные `context` остаются исходными; `context.Rip` нельзя читать как уже изменённый RIP.

### Система координат

- `instruction_site`, `sled_start`: абсолютные метки текущей пробы.
- `instruction_length`: длина известной собственной целевой инструкции; `null` для трёх API-клеток.
- `offset_reference`: `owned_instruction_start` либо `owned_api_call_site`.

В API-клетках относительный адрес отсчитан от собственного CALL, не от найденной trap-инструкции внутри системной DLL. Он может быть большим или отрицательным и не используется для вычисления длины DLL-кода.

## type = run_result

Терминальная запись повтора:

| Поле | Смысл |
|---|---|
| `key` | Ключ повтора |
| `status` | Один из статусов ниже |
| `exception_delivered` | Были ли получены наблюдения; `null`, когда родитель не может установить исход |
| `observation_count` | Число observation для этого ключа |
| `stack_depth` | Глубина повторного вызова |
| `continuation_entry_offset` | Измеренное смещение 0…8 от начала цепочки, либо null |
| `continuation_site_offset` | Та же измеренная точка относительно instruction_site, либо null |
| `post_rax` | Полный RAX из post-снимка, либо null |
| `probe_returned` | Был ли получен возврат собственной пробы |
| `safety_escape` | Использован отдельный защитный путь |
| `reason` | Причина неполного/особого исхода; пустая строка допустима для completed |
| `post_rflags`, `post_rsp`, `pre_rsp` | Дополнительные post/entry значения, присутствуют при возврате |

Статусы:

- `completed`: проба вернулась с измеряемым исходом. Если `exception_delivered=false`, это наблюдаемый случай отсутствия доставки.
- `requested_policy_unsupported`: исходные наблюдения есть, но запрошенную политику нельзя выполнить корректно/безопасно. Реальные действия указаны в observation. Это учтённый ключ, **не успешное измерение запрошенной политики**.
- `guard_escape`: превышен предел доставок; применён собственный защитный выход. Не успешный замер.
- `runtime_aborted`: процесс/проба аварийно закончился, не был создан, завис или не дошёл до повтора. `null`-поля нельзя заменять нулями или «исключения не было».
- `skipped`: схема checker допускает явный пропуск с причиной; основной collector сейчас использует build blocker или runtime_aborted, не подставляет фиктивные успешные записи.

`post_rax` после safety escape может быть сохранён для диагностики, но не доказывает штатное прохождение команды/цепочки. Оба continuation-offset в этом случае `null`.

## type = group_result

Родительский итог одного собственного дочернего процесса:

- `group`: первые четыре поля ключа без повтора.
- `group_index`: номер 0…215 как hex-строка.
- `created`, `create_error`: результат CreateProcess и значимый код ошибки при неуспехе.
- `assigned`, `assign_error`: включение собственного ребёнка в собственный cleanup job.
- `resumed`, `resume_error`: запуск ребёнка после успешного включения в job.
- `reaped`: подтверждено завершение ребёнка.
- `wait_status` и `wait_error`: исходное ожидание ребёнка; исходный тайм-аут остаётся `0x102`. `cleanup_wait_status` и `cleanup_wait_error` описывают отдельное ожидание после попытки завершения. `child_exit_code`, `exit_query_error` и `timeout` записываются отдельно; успешный cleanup не отменяет исходный тайм-аут.
- `child_process_id`, `child_thread_id`: идентификаторы непосредственно созданного ребёнка, включая случай неудачного включения в job.
- Объединение дочернего файла производится только после подтверждённого `reaped=true`; неподтверждённый живой файл остаётся отдельным артефактом.
- `terminate_error`, `exit_query_error`: ошибки собственного TerminateProcess и чтения кода выхода.
- `partial_record_dropped`: при слиянии пропущен незавершённый фрагмент строки.
- `child_terminal_records`: число полностью полученных итогов из файла ребёнка, **до** добавления родителем аварийных итогов недошедших повторов.

Завершение собственного ребёнка после timeout не устраняет неполноту данных. Отдельные group-файлы сохраняются для проверки журнала.

## type = thread_context

Идентичность задаётся четырьмя полями `operation`, `target`, `request`, `phase`:

| operation | target | request | phase |
|---|---|---|---|
| get | current | debug | before |
| get | current | all | before |
| get | suspended | debug | before |
| get | suspended | all | before |
| set | suspended | debug | set_dr7_zero |
| get | suspended | debug | after_set |
| get | suspended | all | after_set |

Дополнительные поля:

- `status`: `observed` либо `skipped`; `success`: BOOL результата вызова.
- `last_error`: сразу прочитанный GetLastError. Перед попыткой он обнулён; после успешного вызова его значение не является самостоятельной ошибкой API.
- `requested_flags`: заданные входные ContextFlags.
- `context`: `ContextFlags`, `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr4`, `Dr5`, `Dr6`, `Dr7`. Dr4/Dr5 всегда `null`, так как таких членов нет в публичном x64 CONTEXT.
- `context_bytes_hex`: фиксированный буфер в порядке памяти.
- `buffer_pattern_byte`: `"0xa5"`; для get это предыстория собственного буфера до задания ContextFlags. Set использует копию успешного DEBUG-снимка, а не свежий patterned-buffer.
- `debug_alias_status`: `Dr4_Dr5_not_present_in_CONTEXT`.
- `validity`: `invalid_current_thread_context`, `requested_fields_only`, `call_failed_no_valid_context` либо `input_debug_snapshot_with_only_Dr7_zeroed`; при пропуске Set из-за отсутствия валидного DEBUG-снимка — `not_attempted_no_valid_debug_snapshot`.

Set-запись описывает отправленный буфер; две `after_set` записи описывают реальные повторные чтения. Неуспешный GetThreadContext не превращает оставшийся узор в настоящий контекст.

## type = thread_cleanup

Изолированный ребёнок малого блока записывает результат завершения своего второго потока:

- `created`, `ready`, `suspended`: был ли поток создан, сообщил о готовности и был приостановлен.
- `resume_success`: завершилась ли необходимая попытка возобновления; если приостановки не было, возобновление не требуется.
- `thread_signaled`: ожидание действительно подтвердило завершение потока.
- `create_error`, `suspend_error`, `resume_error`, `wait_status`: коды соответствующих операций, hex-строки.

Неудачный cleanup не скрывается закрытием дескриптора. Отдельный процесс малого блока ограничивает жизненный цикл такого потока.

## type = thread_block_result

Родительский итог отдельного процесса малого блока. Содержит те же поля жизненного цикла, что group_result: `created`, `assigned`, `resumed`, `reaped`, `timeout`, `create_error`, `assign_error`, `resume_error`, `wait_status`, `wait_error`, `cleanup_wait_status`, `cleanup_wait_error`, `terminate_error`, `child_exit_code`, `exit_query_error`, `child_process_id`, `child_thread_id`, а также `partial_record_dropped`. Не содержит ключ группы, group_index или child_terminal_records, поскольку не входит в матрицу 4320.

## summary.json и код checker

Команда:

```text
python check_results.py raw.jsonl --summary summary.json
```

`summary.json` — производный отчёт, не эталон ожидаемых Windows-значений. Его числовые значения также hex-строки. Разделы включают:

- Происхождение и SHA-256 входного файла.
- Синтаксические/структурные ошибки с номерами строк и ключами.
- Ожидаемую матрицу 4320 и полные списки отсутствующих, дублированных, неподдержанных, пропущенных и аварийных ключей.
- Раздельные `coverage_complete` и `all_runs_measured`: учтённая unsupported-клетка не делает её measured.
- Случаи отсутствия доставки, полноту 216 group_result, семь thread-context операций и обе служебные записи их жизненного цикла.
- Изменчивость полей exception/context/xstate/gpr_differences для одинакового номера доставки, отдельно между глубинами и внутри глубины. Один образец не объявляется доказанной стабильностью.

Коды checker: `0` — структура корректна и все ключи приемлемо учтены, включая явно unsupported; `1` — нарушение проверки, отсутствие/пропуск, runtime_aborted или guard_escape; `2` — ошибка ввода-вывода или команды. Summary по возможности создаётся также при неуспехе. Необязательный `--allow-incomplete` смягчает только отсутствие/явные пропуски; malformed/aborted остаются ошибками. PowerShell этот параметр **не использует**.

Коды PowerShell: `0` — сборка, программа и строгая проверка завершились успешно; `1` — ошибка запуска/данных/проверки; `2` — блокер окружения, компилятора или сборки. Успешный код 0 не отменяет явно перечисленных unsupported-клеток: для научного сравнения нужно читать полноту измерений, не только код процесса.
