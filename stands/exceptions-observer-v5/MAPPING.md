# Карта v5 → измеряемый путь

Это карта областей сравнения, не установленная трасса закрытого Windows и не патч.

| Часть | Клетки | Поля для сравнения | Возможные точки собственной Wine/FEX реализации |
|---|---|---|---|
| 1 | 12 фиксированных RAX, INT 2D | факт доставки, incoming RAX, ExceptionAddress/RIP, continuation offset, все post-GPR, первый PUSHFQ image | INT 2D decode/execute; KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| 2a | INT 2D/0, INT 2D/own-stack, CC | incoming RIP, literal proposed RIP+len, actual RIP, post-state | восстановление контекста и NtContinue |
| 2b | те же 3 | переход на alternate own landing, соответствие кадра, post-state | восстановление RIP/GPR/EFlags |
| 2c | те же 3 | второй 0x80000004, адрес/offset, incoming TF и Dr6, first/last PUSHFQ images | single-step, debug state, доставка следующего trap |
| 2d | те же 3 | VEH SEARCH → реальный рамочный SEH, общий delivery id, разные callback ordinal | порядок dispatch/search, frame SEH |
| 2e | те же 3 | VCH called/count/order без требуемого ответа | vectored continue dispatch |
| 3 | пять API собственного процесса | 15 raw слотов параметров с valid count, own-symbol references, DLL location без offset, типизированный результат, место собственного возврата | DebugBreak/OutputDebugString; RtlRaiseException/NtRaiseException и связанные API |

В части 2 действия advance/alternate/TF/VCH применяются с VEH, SEH, UEF; цепочка VEH→SEH — одна отдельная observer-пара. Базовое продолжение в routing/VCH-клетках — guarded literal incoming RIP+length. TF дополнительно ставит RIP в начало собственной цепочки. Часть 3 использует только VEH и неизменённый внутренний RIP. Полный закрытый список приведён в DESIGN.md и checker.

## Что можно предсказать заранее

- Публичный контракт API определяет типы возврата и смысл CheckRemoteDebuggerPresent: результат вызова и out BOOL различны. Void-функции не имеют C return value. Он не устанавливает полный внутренний VEH/VCH trace.
- Архитектура PUSHFQ определяет неизменность арифметических флагов и очистку RF/VM в сохранённом образе; это свойство собственного измерителя, не ответ Windows об INT 2D.
- INT 2D service dispatch по 12 новым значениям нельзя объявлять измеренным Windows-эталоном. В отдельном обзоре Wine на a15ee2ccf2 все эти значения попадают в default ветвь полного RAX; это прогноз **Wine**, не результат Windows.
- TF/Dr6/точные адреса/порядок наблюдателей, pointer-like RAX и поведение API на конкретных windows-2022/windows-2025 до native run остаются измеряемыми величинами. Отсутствие доставки может быть полноценным результатом, а guard/unsupported — ограничением измерения.

Часть 4 поставляется отдельно: открытые исходники, коммиты, строки и архив различий. В этот v5-пакет не включён код Wine/FEX.

## Старые результаты и часть 5

Пользователь сообщил, что прежние 21 клетки совпали на двух Windows-машинах: RAX=0/2/0x10 доставляли исключение и продолжались с +2; 1/3/4/5 продолжались с +3 без доставки. Это **сообщённый пользователем** результат, не воспроизведение этой поставкой.

Сырьё v4 ещё не получено. Здесь нет выдуманной сверки v4, автоматической подстановки этой таблицы в checker или старых 4 320 запусков в матрицу v5. Сравнение v4 по полям выполняется отдельно после получения обоих raw-файлов.
