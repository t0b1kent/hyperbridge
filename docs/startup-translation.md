# Where Hollow Knight's start-up goes: translation cost under HyperBridge

Measurements of 29 September 2026, Apple M1 Pro, macOS 27, MacRunner's Wine, HyperBridge engine 0019 (FEX-Emu
`fd141ed6d` + patches 0001–0019) with experimental patches that are not part of the published series yet. Game:
Hollow Knight 1.5.12620 (Unity, Mono), start to the main menu, no input. Every comparison is an interleaved series
on one binary (3 runs per arm unless noted); ranges are min–max.

## 1. A record of every translation, and a replay stand

The engine can write every block translation of a run to a file (experimental gate `MACRUNNER_FEX_CAPTURE`): guest
address, decoder limits, the 4 KiB guest code pages the decoder read (content once per hash), the answers the
frontend gave about executable and writable ranges during that translation, the resulting block shape, and the IR
and code generation time.

A native macOS program built from the same FEXCore source (`hb_replay`) maps those pages back at their original
addresses and translates every block again, without Wine and without the game. On the Hollow Knight record
(149 760 translations):

- block shape (instruction count, start, length) matches the game for 149 760 of 149 760 translations;
- built as ARM64EC, it emits the same ARM64 code, byte for byte, for 99.3 % of the blocks (the rest differ by
  8–48 bytes at exits into ARM64EC code, whose map the stand does not have), and its code generation time equals
  the game's (1 623 ms against 1 620 ms);
- the whole record replays in about 7 seconds instead of a two-minute game run, and the emitted code is
  deterministic to the byte within an arm, so translator changes can be compared without game noise.

The stand measures translation only (about 11 s of thread time of a 40 s start), not the speed of the translated
code, Wine or graphics.

## 2. What the record shows

| Translations until the main menu | count | share | IR + codegen (thread time) |
|---|---:|---:|---:|
| first translation of an address | 70 196 | 46.9 % | 2.18 s |
| same address, same pages, same range answers | 44 101 | 29.4 % | 2.77 s |
| same address, page changed, block bytes unchanged | 21 796 | 14.6 % | 0.63 s |
| block bytes changed (new code at the same address) | 8 366 | 5.6 % | 0.77 s |
| same bytes, different writability | 4 765 | 3.2 % | 0.29 s |

By kind of code: DLL images (read-only executable) account for 63 153 translations, of which 33 630 re-translate
unchanged image code; code that Mono generates at run time (read-write-executable) for 86 607. By module, 68 % of
the translation time goes to Mono's generated code and 28 % to `UnityPlayer.dll`.

The main cause of the re-translations is code size. With the default check of code in writable memory (every
instruction in writable code is compared byte for byte before it runs), the engine emitted 641–661 MB of ARM64
code during the start (85 bytes per x86 instruction); the 128 MB code buffer filled up and was flushed 7 times, and
after each flush all hot code, including unchanged DLL images, was translated again.

## 3. Checks of writable code

`MACRUNNER_FEX_WRITABLE_VALIDATION`: 1 (default) checks every instruction in writable code; 2 checks only on 16 KiB
host pages that are not entirely inside a read-write-executable range (the mixed pages where write tracking cannot
see writes); 3 is 2 plus checks of control-transfer instructions.

On the replay stand (cost of one translation of the same 149 760 blocks):

| mode | IR | code generation | ARM64 code |
|---|---:|---:|---:|
| 1 | 3 551 ms | 1 651 ms | 680.8 MB |
| 2 | 2 374 ms | 501 ms | 110.3 MB |
| 3 | 2 523 ms | 647 ms | 202.2 MB |
| 0 (no checks) | 2 383 ms | 518 ms | 110.3 MB |

The checks are 83.8 % of the code emitted in mode 1. On Hollow Knight mode 2 is byte for byte equal to mode 0: all
of the game's writable code lies in whole 16 KiB host pages. That also means Hollow Knight says nothing about
whether mode 2 is safe for programs that rewrite their own code (mode 2 has a known failure on Elden Ring's Arxan
protection, which is why mode 3 exists).

In the game: time to the main menu 38.7–46.8 s in mode 1 against 33.0–33.3 s in mode 2 (every mode 2 run faster
than every mode 1 run); 147 456 translations against 118 784; 7 buffer flushes against 2.

## 4. IR by stage (replay stand, IR stage timers)

| stage | mode 1 | mode 2 |
|---|---:|---:|
| whole IR generation | 4 004 ms | 2 627 ms |
| decoding | 791 ms | 758 ms |
| building the IR | 1 622 ms | 759 ms |
| dead flags pass | 587 ms | 371 ms |
| register allocation | 959 ms | 695 ms |

The stages add up to the total within 1–1.6 %. Mode 1 costs 1 378 ms more, 63 % of it in building the IR.

## 5. The executable-range query

The writable-code check asked the frontend for the executable range of every x86 instruction: 7.8 million queries
until the menu, about 100 ns each in the game (in the replay stand the answer is a vector lookup, which is why IR
there was 3.5 s against 5.0 s in the game). An experimental gate answers from the range the decoder has already
cached; on the stand the emitted code is unchanged byte for byte for all 149 760 translations, and in the game IR
thread time drops by 18 % (mode 1: 4 606 → 3 781 ms) and 21 % (mode 2: 2 137 → 1 691 ms). Time to the menu did not
change measurably: after the mode 2 change the start is no longer bound by translation.

A later check on a Stardew Valley record (.NET/CoreCLR) found the gate unsafe: 4 of 6 655 translations were emitted
without the writable-code check. The cause is in the range answer itself. For a non-writable address the frontend
was told [start of the executable interval, next writable interval), and that range can cover a writable page lying
*before* the address inside the same interval (here a 4 KiB writable page inside a 3.7 MiB image range). The decoder
caches the answer, the gate reused it, and so do FEX-Emu's own Mono decisions that read the cached writability.
An experimental patch makes a non-writable answer start at the queried address; its check on the stand is pending.
The Hollow Knight, ABZU, Divinity and Hedon records emit the same code with and without the gate.

## 6. Mono call-site patches

Mono (Unity's C# runtime) compiles a method on its first call and then rewrites the call site to point at the
compiled code: the 8-byte immediate of `mov r11, imm64; call r11` (`49 BB <imm64> 41 FF D3`). Until the main menu
Hollow Knight does this 17 233 times (plus 29 `call rel32` patches), counted from the differences between guest code
page snapshots in the translation record.

FEX-Emu recognises Mono's patching function after the first write faults, translates it again so that its store
goes through `MonoBackpatcherWrite`, and turns off write traps for all writable code. `MonoBackpatcherWrite`
invalidates the whole 4 KiB page around the patched bytes, and every thread whose lookup cache held a block of that
page zeroes its 4 MiB call-return stack under the exclusive code lock. Per start: about 17 000 page invalidations,
17 000 call-return stack clears (1.17 s of thread time) and 29 000 re-translations of unchanged neighbour blocks.

**A defect in an experimental gate.** The gate that returns an earlier translation by hash when the guest bytes are
unchanged (`MACRUNNER_FEX_REVIVE`) returned the translation of Mono's patching function made *before* it was
recognised. Its bytes had not changed, so the hash matched, but the recognition changes what the translation must
contain. From then on patches were plain stores with the write traps already off: nothing was invalidated, and the
translations of patched call sites kept calling the old target. The start looked much cheaper (37 re-translations
instead of 29 000) while running stale code. Fixed: recognising the patching function now empties the gate's table.
The general rule: anything that hands out a ready translation (reuse by hash, a persistent code cache) must key on
every state that changes the translation of the same bytes.

**Precise invalidation for call-target patches** (experimental gate `MACRUNNER_FEX_MONO_BP_PRECISE`). Every
translation records the guest bytes it covers. When a patch has the call-target pattern above, only translations
covering the 8 patched bytes are dropped, and call-return stacks are left alone: an older translation differs only
in the call target, so returning into it calls Mono's previous target (its trampoline), which is what a core that
has not yet observed the cross-modification would do. Other writes of the patching function keep the old path.

One binary, write-code check mode 2, 128 MB code buffer, main menu, two runs per arm:

| arm | menu (s) | translations | re-translations | page invalidations | call-return clears |
|---|---:|---:|---:|---:|---:|
| baseline | 30.3, 29.8 | 98 304 | 29 103 | 17 326 | 16 954 (1 172 ms) |
| precise invalidation | 27.3, 28.1 | 77 824 | 8 464 | 464 | 66 (5 ms) |
| reuse by hash (fixed) | 28.4 | 77 824 | 8 448 | 17 366 | 17 019 (1 175 ms) |
| reuse by hash, old defect | 29.2 | 69 632 | 40 | 407 | 7 |

With the old defect not a single patch reached `MonoBackpatcherWrite` (0 against 16 961), which is the direct proof
of the mechanism. Precise invalidation alone removes as many translations as reuse by hash and 99.6 % of the
call-return clears; the menu came 2.3 s (8 %) earlier in these runs, every precise run faster than every baseline
run. Two runs per arm — a preliminary result.

## 7. What is left

- 46.9 % are first translations; only a cache kept between runs removes them. FEX-Emu has an experimental code
  cache; for DLL images the ceiling on this record is 1.06 s of thread time (2.18 s of first translations in
  total), and up to 3.6 s if repeated image translations also come from the cache.
- The remaining ~8 400 re-translations are mostly the patched blocks themselves; they disappear only if a patch
  needs no invalidation at all (retargeting the block link in place, or reading the call target from guest memory).
- Clearing the call-return stack on other invalidations still costs a 4 MiB write each time; tagging entries with
  a per-thread generation would make old entries stop matching without clearing anything.

These patches are experimental and not part of the published series; the numbers are for one game and one machine.
