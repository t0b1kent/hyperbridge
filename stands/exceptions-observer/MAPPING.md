# Сопоставление с проверяемой реализацией

Это карта для последующего ручного сравнения одной и той же пользовательской пробы. Имена ниже взяты из постановки задачи. Это **не трасса вызовов Windows** и не утверждение, что каждый запуск проходит каждую названную функцию: наличие исключения и выбранный путь остаются предметом измерения.

В столбце функций даны только имена. Исходники, ревизии, фрагменты кода и тесты Wine не использованы и не включены.

| Клетка/вариант | Имена функций |
|---|---|
| INT3 `CC` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 3 `CD 03` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x0` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x1` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x2` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x3` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x4` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x5` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2D, RAX=`0x10` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| ICEBP `F1` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| DebugBreak() | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| RaiseException(), 0 параметров | RtlRaiseException, NtRaiseException, KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| RaiseException(), 1 параметр | RtlRaiseException, NtRaiseException, KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| TF + короткая команда | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| UD2 `0F 0B` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 2C `CD 2C` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| HLT `F4` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| INT 1 `CD 01` | KiUserExceptionDispatcher, RtlDispatchException, NtContinue |
| GetThreadContext(), текущий собственный поток | NtGetContextThread |
| GetThreadContext(), приостановленный собственный поток | NtGetContextThread |
| SetThreadContext(), Dr7=0, собственный приостановленный поток | NtSetContextThread |
| Повторный GetThreadContext() после SetThreadContext() | NtGetContextThread |

Для INT3, INT 2D и ICEBP байты собственной функции одновременно служат входом будущему переводчику x86-64 → ARM64. Различия «была ли доставка», в полном RAX после инструкции и в точке входа в цепочку надо сравнивать раздельно. Остальные команды и API дают контрольные пути доставки и восстановления контекста.

VEH, рамочный SEH и UEF проверяются отдельными проходами, чтобы результат одного наблюдателя не был результатом уже изменённого другим наблюдателем контекста.
