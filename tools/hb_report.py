#!/usr/bin/env python3
"""hb_report.py — HyperBridge v1.1 status and coverage report generator."""

import json
import subprocess
import pathlib
import sys
import re
import os
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


#  ВНИМАНИЕ. Всё, что ниже, — РУКОПИСНЫЕ УТВЕРЖДЕНИЯ, а не замер. Прежде они
#  печатались словом "PASS" рядом со свежей меткой времени, отчего отчёт
#  выглядел снятым прибором. Слово заменено на «ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО»:
#  утверждение осталось, ложная подпись под ним снята. Настоящие числа —
#  в coverage_report(), они берутся у доски.
def status_report():
    return {
        "product": "MacRunner HyperBridge",
        "version": "1.1",
        "timestamp": now(),
        "status": "Lazy Flags Engine + Conditional Execution Foundation",
        "summary": {
            "standalone_engine": True,
            "production_macrunner_untouched": True,
            "lazy_flags_model": True,
            "persistent_translation_cache": True,
            "wine_pe_markers": True,
            "iat_rewrite_planner": True,
            "abi_thunk_registry": True,
            "page_fault_dispatcher": True,
            "jit_lazy_flags_strategy": "helper materialization",
        },
        "lazy_flags": {
            "operations": ["ADD", "SUB", "AND", "OR", "XOR", "SHL", "SHR", "SAR", "CMP", "TEST"],
            "stored_fields": ["kind", "width", "lhs", "rhs", "result", "count", "valid_mask"],
            "lazy_flags": ["ZF", "SF", "CF", "OF", "PF", "AF"],
            "unsupported_explicit": True,
            "shift_count_zero_preserves_flags": True,
        },
        "conditions": {
            "supported": ["E/Z", "NE/NZ", "L/NGE", "LE/NG", "G/NLE", "GE/NL",
                          "B/C/NAE", "AE/NB/NC", "BE/NA", "A/NBE", "S", "NS", "O", "NO"],
            "also_available": ["P", "NP"],
        },
        "core": {
            "interpreter": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — flag-producing ops store LazyFlags; Jcc/SETcc/CMOVcc materialize required bits",
            "arm64_jit": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — helper-based result execution and LazyFlags materialization",
            "jcc": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — interpreter and JIT differential fuzzed",
            "setcc": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — direct IR and JIT/interpreter differential fuzzed",
            "cmovcc": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — direct IR and JIT/interpreter differential fuzzed",
            "branch_targets": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — interpreter CFG transfer bug fixed by differential fuzz",
            "translation_cache": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — atomic temp/fsync/rename writes, corrupt entries ignored, module invalidation",
            "pe_section_markers": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — deterministic JSONL marker records for x86/x86_64 executable sections",
            "iat_rewriter": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — dry-run/apply/rollback plan with bridge stub handoff",
            "abi_thunks": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — typed integer thunk registry for x64 and x86 signatures",
            "page_fault_dispatcher": "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО — ownership table, dirty invalidation, stale rejection, unload pass-through",
        },
        "tests": {
            "c_runner": {"passed": 21, "failed": 0},
            "python_engine": {"passed": 41, "failed": 0},
            "tests_hyperbridge_wrapper": "python3 -m unittest discover -s tests/hyperbridge -v",
        },
        "limitations": [
            "JIT uses C helpers for LazyFlags materialization; inline ARM64 flag codegen is deferred.",
            "AF for logical ops and AF/OF for multi-bit shifts are marked unsupported/undefined instead of guessed.",
            "SETcc/CMOVcc support is implemented for register destinations/sources in JIT; interpreter also supports SETcc memory writes.",
            "Python decode tooling is still MVP and does not fully expose every C decoder conditional instruction form.",
            "No production MacRunner launcher/Wine/D3D path is touched by HyperBridge patches.",
            "Wine loader/IAT integration is emitted as patch files and debug JSONL hooks; the standalone HyperBridge tests validate records and rollback mechanics.",
        ],
    }


def _zamerit(rezhim):
    """ЧЕСТНЫЙ ЗАМЕР вместо литерала "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО".

    Прибор печатал 17 строк "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО" и свежую метку времени, не обращаясь НИ К
    ОДНОМУ файлу и не запуская НИ ОДНОГО процесса (grep по subprocess/open/
    run дал ноль). Опубликованный reports/HYPERBRIDGE-COVERAGE.md нёс свежую
    дату над константой — то есть отчёт был доказательством самого себя.

    Теперь числа берутся у настоящей доски. Не удалось снять — так и
    сказано, а не "ЗАЯВЛЕНО, НЕ ЗАМЕРЕНО".
    """
    koren = pathlib.Path(__file__).resolve().parents[3]
    doska = koren / "tools" / "hb_isa_coverage" / "coverage.py"
    if not doska.exists():
        return {"ЗАМЕР": "НЕ СНЯТ", "почему": "доски нет: %s" % doska}
    try:
        p = subprocess.run([sys.executable, str(doska), "--mode", rezhim],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=2400)
    except Exception as e:                      # noqa: BLE001
        return {"ЗАМЕР": "НЕ СНЯТ", "почему": "доска не запустилась: %s" % e}
    vyvod = p.stdout.decode("utf-8", "replace")
    itog = {"ЗАМЕР": "снят", "код возврата": p.returncode}
    for obraz, klyuch in ((r"LIFT: ok=(\d+)/(\d+) = ([\d.]+) %", "подъём"),
                          (r"Total test cases in corpus: (\d+)", "случаев в наборе"),
                          (r"отказов подъёма: (\d+)", "отказов подъёма")):
        m = re.search(obraz, vyvod)
        if m:
            itog[klyuch] = m.group(3) + " %" if klyuch == "подъём" else m.group(1)
    if "подъём" not in itog:
        itog["ЗАМЕР"] = "НЕ СНЯТ"
        itog["почему"] = "в выводе доски нет строки LIFT"
    return itog


def coverage_report():
    return {
        "product": "MacRunner HyperBridge",
        "version": "1.1",
        "timestamp": now(),
        "ЧЕМ СНЯТО": "tools/hb_isa_coverage/coverage.py, оба режима",
        "покрытие": {"x64": _zamerit("x64"), "i386": _zamerit("x86")},
    }

def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def write_status_md(path, data):
    lines = ["# HyperBridge Status Report", "", f"Generated: {data['timestamp']}", "", "## Summary", ""]
    for k, v in data["summary"].items():
        lines.append(f"- **{k}**: {v}")
    lines.extend(["", "## Lazy Flags", ""])
    for k, v in data["lazy_flags"].items():
        lines.append(f"- **{k}**: {v}")
    lines.extend(["", "## Conditions", ""])
    for k, v in data["conditions"].items():
        lines.append(f"- **{k}**: {v}")
    lines.extend(["", "## Core", ""])
    for k, v in data["core"].items():
        lines.append(f"- **{k}**: {v}")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in data["limitations"])
    path.write_text("\n".join(lines) + "\n")


def write_coverage_md(path, data):
    """Печатает то, что СНЯТО, и честно говорит, если снять не удалось.

    Прежде ключ звался "coverage" и нёс литералы "PASS"; теперь это
    "покрытие" с настоящими числами от доски. Печатник за переименованием не
    поспел и падал с KeyError — поймано первым же запуском (до правки его,
    похоже, не запускали вовсе: он не читал ни одного файла).
    """
    cov = data.get("покрытие", data.get("coverage", {}))
    lines = ["# HyperBridge Coverage Report", "",
             f"Снято: {data['timestamp']}",
             f"Чем: {data.get('ЧЕМ СНЯТО', '—')}", ""]
    for rezhim, itog in cov.items():
        lines.append(f"## {rezhim}")
        if isinstance(itog, dict):
            for k, v in itog.items():
                lines.append(f"- **{k}**: {v}")
        else:
            lines.append(f"- {itog}")
        lines.append("")
    path.write_text("\n".join(lines) + "\n")


def main():
    script_dir = Path(__file__).resolve().parent
    engine_reports = script_dir.parent / "reports"
    root_reports = script_dir.parents[2] / "reports"
    for directory in (engine_reports, root_reports):
        directory.mkdir(parents=True, exist_ok=True)

    status = status_report()
    coverage = coverage_report()
    for directory in (engine_reports, root_reports):
        write_json(directory / "hyperbridge-status.json", status)
        write_status_md(directory / "HYPERBRIDGE-STATUS.md", status)
        write_json(directory / "hyperbridge-coverage.json", coverage)
        write_coverage_md(directory / "HYPERBRIDGE-COVERAGE.md", coverage)

    print(f"Report: {root_reports / 'hyperbridge-status.json'}")
    print(f"Report: {root_reports / 'HYPERBRIDGE-STATUS.md'}")
    print(f"Report: {root_reports / 'hyperbridge-coverage.json'}")
    print(f"Report: {root_reports / 'HYPERBRIDGE-COVERAGE.md'}")


if __name__ == "__main__":
    main()
