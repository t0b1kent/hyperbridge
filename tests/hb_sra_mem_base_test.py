#!/usr/bin/env python3
"""Check the actual SRA fault veto against words from Apple's ARM64 assembler.

The C functions are extracted from production source instead of duplicating the
decoder in the test. Two deliberate omissions must fail the same corpus.
"""

from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def function(source, name):
    start = re.search(r"^static (?:int|bool) " + name + r"\(", source, re.M).start()
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def corpus():
    cases = []
    for base in (21, 22, 19, 31, 0, 30):
        address = "sp" if base == 31 else "x%d" % base

        def add(insn, family):
            cases.append((insn.replace("BASE", address), base, family))

        for width in ("w", "x"):
            for op in ("stlr", "ldar", "ldxr", "ldaxr"):
                add("%s %s4, [BASE]" % (op, width), "exclusive")
            for op in ("stxr", "stlxr"):
                add("%s w6, %s4, [BASE]" % (op, width), "exclusive")
            for op in ("ldxp", "ldaxp"):
                add("%s %s4, %s5, [BASE]" % (op, width, width), "exclusive")
            for op in ("stxp", "stlxp"):
                add("%s w6, %s4, %s5, [BASE]" % (op, width, width), "exclusive")
            for order in ("", "a", "l", "al"):
                add("cas%s %s4, %s6, [BASE]" % (order, width, width), "exclusive")
                add("casp%s %s4, %s5, %s6, %s7, [BASE]" %
                    (order, width, width, width, width), "exclusive")
            add("ldapr %s4, [BASE]" % width, "lse")
            for op in ("ldadd", "swp", "ldclr", "ldeor", "ldset",
                       "ldsmax", "ldsmin", "ldumax", "ldumin"):
                for order in ("", "a", "l", "al"):
                    add("%s%s %s4, %s6, [BASE]" %
                        (op, order, width, width), "lse")

        for size in ("b", "h"):
            for op in ("stlr", "ldar", "ldxr", "ldaxr"):
                add("%s%s w4, [BASE]" % (op, size), "exclusive")
            for op in ("stxr", "stlxr"):
                add("%s%s w6, w4, [BASE]" % (op, size), "exclusive")
            for order in ("", "a", "l", "al"):
                add("cas%s%s w4, w6, [BASE]" % (order, size), "exclusive")
            add("ldapr%s w4, [BASE]" % size, "lse")
            for op in ("ldadd", "swp", "ldclr", "ldeor", "ldset",
                       "ldsmax", "ldsmin", "ldumax", "ldumin"):
                for order in ("", "a", "l", "al"):
                    add("%s%s%s w4, w6, [BASE]" % (op, order, size), "lse")

        for width in ("w", "x", "b", "h", "s", "d", "q"):
            for op in ("ldr", "str"):
                add("%s %s4, [BASE, #16]" % (op, width), "existing")
                add("%s %s4, [BASE, x6]" % (op, width), "existing")
            for op in ("ldur", "stur"):
                add("%s %s4, [BASE, #-8]" % (op, width), "existing")
        for width in ("w", "x", "q"):
            for op in ("ldp", "stp"):
                add("%s %s4, %s5, [BASE, #16]" % (op, width, width), "existing")
        for op in ("ldrb", "strb", "ldrh", "strh"):
            add("%s w4, [BASE, #16]" % op, "existing")

    for insn in ("add x4, x21, x6", "sub x4, x21, #8", "and x4, x21, x6",
                 "orr x4, x21, x6", "eor x4, x21, x6", "mul x4, x21, x6",
                 "cmp x21, x6", "csel x4, x21, x6, eq", "br x21", "ret x21",
                 "nop", "dmb ish", "dsb ish", "clrex", "mrs x4, nzcv"):
        cases.append((insn, -1, "nonmemory"))
    return cases


def main():
    source = (ROOT / "src/hb_arm64_codegen.c").read_text()
    scanner = function(source, "sra_insn_mem_base")
    fault = function(source, "sra_block_can_fault")
    cases = corpus()
    with tempfile.TemporaryDirectory(prefix="hb-sra-mem-") as temporary:
        directory = Path(temporary)
        assembly = directory / "cases.s"
        obj = directory / "cases.o"
        assembly.write_text(".text\n" + "\n".join(case[0] for case in cases) + "\n")
        run(["clang", "-c", "-arch", "arm64", "-march=armv8.3-a",
             str(assembly), "-o", str(obj)])
        raw = run(["otool", "-t", str(obj)]).stdout
        words = []
        for line in raw.splitlines():
            parts = line.split()
            if parts and re.fullmatch(r"[0-9a-fA-F]{16}", parts[0]):
                if not all(re.fullmatch(r"[0-9a-fA-F]{8}", word) for word in parts[1:]):
                    raise RuntimeError("unexpected otool instruction format: " + line)
                words.extend(int(word, 16) for word in parts[1:])
        if len(words) != len(cases):
            raise RuntimeError("assembler emitted %d words for %d cases" % (len(words), len(cases)))
        ctx_load = words[next(i for i, case in enumerate(cases)
                              if case[0] == "ldr x4, [x19, #16]")]

        prefix = """#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef struct { const uint8_t *code; size_t size; } hb_codegen_buffer_t;
"""
        driver = """
int main(void) {
    uint32_t words[2];
    hb_codegen_buffer_t buf = {(const uint8_t *)words, sizeof(words)};
    while (scanf("%x", &words[0]) == 1) {
        /* A safe ctx load preceding the tested instruction must not hide it. */
        words[1] = words[0]; words[0] = CTX_LOAD_WORD;
        printf("%d %d\\n", sra_insn_mem_base(words[1]), sra_block_can_fault(&buf));
    }
    return 0;
}
""".replace("CTX_LOAD_WORD", "0x%08xu" % ctx_load)
        variants = [("normal", scanner)]
        for family in ("exclusive", "lse"):
            marker = " /* sra-memory-class: %s */" % family
            if scanner.count(marker) != 1:
                raise RuntimeError("missing unique negative-control marker: " + family)
            broken = "\n".join(line for line in scanner.splitlines() if marker not in line)
            variants.append((family, broken))

        results = {}
        for variant, implementation in variants:
            cfile = directory / (variant + ".c")
            binary = directory / variant
            cfile.write_text(prefix + implementation + "\n" + fault + driver)
            run(["clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 str(cfile), "-o", str(binary)])
            output = run([str(binary)], input="\n".join("%08x" % w for w in words)).stdout
            actual = [tuple(map(int, line.split())) for line in output.splitlines()]
            if len(actual) != len(cases):
                raise RuntimeError("decoder did not return one result per case")
            failures = []
            for case, word, decoded in zip(cases, words, actual):
                insn, base, family = case
                expected = (base, int(base not in (-1, 19, 31)))
                if decoded != expected:
                    failures.append((insn, family, word, expected, decoded))
            results[variant] = len(failures)
            if variant == "normal" and failures:
                for insn, family, word, expected, decoded in failures[:12]:
                    print("FAIL %s (%08x): expected %s got %s" % (insn, word, expected, decoded))
                raise RuntimeError("%d/%d SRA memory cases failed" % (len(failures), len(cases)))
            if variant != "normal":
                expected_failures = sum(case[2] == variant for case in cases)
                if len(failures) != expected_failures or any(f[1] != variant for f in failures):
                    raise RuntimeError("negative control %s caught %d instead of %d cases" %
                                       (variant, len(failures), expected_failures))
        print("SRA memory-base: %d assembler cases, 0 mismatches; negative controls "
              "exclusive=%d, lse/ldapr=%d detected" %
              (len(cases), results["exclusive"], results["lse"]))


if __name__ == "__main__":
    main()
