# Абсолютные оракулы x86: маски EVEX и флаги

Ответы записаны на настоящем x86 (Астра, 26.09.2026): это не сравнение JIT с
интерпретатором, а сверка ОБОИХ исполнителей HB с железом. Формат записей — `FORMATS.md`.

| раннер | формат | что сверяет |
|---|---|---|
| `tests/hb_mask_state_test` (`hb_mask_audit/`) | HBUP0002 | 32 × 512 бит векторов, 256 байт памяти, отказ доступа на странице-ловушке |
| `tests/hb_flags_state_test` (`hb_flags_oracle/`) | HBFL0001 | шесть регистров и RFLAGS; неопределённые флаги маскируются по руководству |

`common.h` — общий стенд: контекст, подъём программы блок за блоком (`hb_run_program`),
флаги в `ctx->flags` и отложенной записи. Генераторы (`generate*.py`, `native*.S`,
`native_oracle.c`) исполняются на x86 и корпус на Mac не пересобирают.

## В `make test`

Корпуса `corpus/*.gz` (SHA256 несжатых):

```
e1c3e5cd42181fd8723fd970018c592cbe7afea269f924a501931213387948f6  flags-carry-boundaries.hbfl     500
88abdddf54bff7cea2e94d783c3399d98167e26f9918d38f51bec42e7d42975a  flags-smoke.hbfl              19 588
8c6005ae90f08bfcfc501824c33992c3ad6ed057fa99fddc173ff4ff8c80f163  store-loop.hbup                  585
a1817ecc969cff81af9334b072308c9fd71abae2cfcac272e9a4174cfbf57a83  masks-smoke.hbup               9 883
```

`check_summary.py` требует ноль расхождений у обоих исполнителей и не даёт расти числу
неподдержанных форм. В masks-smoke их 528 — EVEX-преобразования (`vcvtdq2ps`, `vcvtps2pd`,
`vcvtps2dq`, `vcvttps2dq`, `vcvtpd2ps`, `vcvtdq2pd`, `vcvtss2sd`, `vcvtsd2ss`), которых в HB нет.

## Полные корпуса

В репозиторий не входят (60 МБ): маски — 46 шардов, 93 839 случаев; флаги — 1 428 шардов,
5 845 506 случаев. Сводный отпечаток (`cd <каталог> && shasum -a256 *.gz | shasum -a256`):

```
masks  5e944a66c2a9a4e1075085f8a838d5c1c709e75d44b7ffd6b464323e74320955
flags  303f87cb5ce0013203c21b8fd13c3e54b15f760c9ecc499a73ec30018b26d520
```

```bash
MACRUNNER_HB_JIT_DIRECT_MEM=1 python3 tests/hb_absolute/replay_shards.py \
  --runner tests/hb_mask_state_test --corpus <каталог>/masks --out tests/hb_mask_audit/out/mac
```

Замер 26–27.09.2026 на Mac (M-серия):
- маски: исполнено 87 791 из 93 839 у каждого исполнителя, расхождений 0; 6 048 — те же
  EVEX-преобразования;
- флаги: 5 845 506 из 5 845 506 у каждого исполнителя, расхождений 0 (все 1 428 шардов).

## Что оракулы нашли на Mac

| где | до | после |
|---|---|---|
| EVEX disp8×N в декодере (store-loop, обе стороны) | 569 из 585 | 0 |
| M01/M02 без правок, store-loop (JIT) | 441 из 585 | 0 |
| M01/M02 без правок, masks-smoke | 1 260 INTERP / 1 594 JIT | 0 |
| M01 без правки, класс масок в `hb_upper_audit` (JIT, low128) | 54 | 0 |
| `rcl/rcr r32, cl` при CL&31 = 0 (flags-smoke, обе стороны) | 260 из 19 588 | 0 |
| 8-бит `adc/sbb` (OF), `sar` (CF), `rol/ror` (CF), полный корпус, 50 шардов | 12 771 из 204 800 | 0 |
