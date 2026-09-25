#!/usr/bin/env python3
"""test_x86.py — x86 decode, lift, run end-to-end tests."""

import unittest
import subprocess
import os
import json


class TestX86DecodeLiftRun(unittest.TestCase):
    def _decode(self, hex_str):
        tool = os.path.join(os.path.dirname(__file__), '..', 'tools', 'hb_decode.py')
        cmd = ["python3", tool, "--arch", "x86", "--hex", hex_str, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def _lift(self, hex_str):
        tool = os.path.join(os.path.dirname(__file__), '..', 'tools', 'hb_lift.py')
        cmd = ["python3", tool, "--arch", "x86", "--hex", hex_str, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def _run(self, hex_str):
        tool = os.path.join(os.path.dirname(__file__), '..', 'tools', 'hb_run.py')
        cmd = ["python3", tool, "--arch", "x86", "--hex", hex_str, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_x86_decode_mov_reg_reg(self):
        out = self._decode("89c8")
        self.assertEqual(out["arch"], "x86")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "MOV")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 4)
        self.assertEqual(insn["op2"]["reg"], 1)
        self.assertEqual(insn["op2"]["size"], 4)

    def test_x86_lift_mov_imm32(self):
        out = self._lift("b805000000")
        self.assertEqual(out["arch"], "x86")
        self.assertEqual(len(out["blocks"]), 1)
        ir = out["blocks"][0]["instrs"][0]
        self.assertEqual(ir["op"], "MOV")
        self.assertEqual(ir["dst"]["reg"], 0)
        self.assertEqual(ir["src"]["value"], 5)

    def test_x86_run_mov_imm32(self):
        out = self._run("b805000000")
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["regs"]["0"], 5)

    def test_x86_run_add_imm8(self):
        out = self._run("b80500000083c003")
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["regs"]["0"], 8)
        self.assertFalse(out["flags"]["zf"])

    def test_x86_run_push_pop(self):
        out = self._run("b80a000000505bc3")
        self.assertEqual(out["status"], "RET")
        self.assertEqual(out["regs"]["0"], 10)
        self.assertEqual(out["regs"]["3"], 10)

    def test_x86_run_sub_flags(self):
        out = self._run("b80500000083e805")
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["regs"]["0"], 0)
        self.assertTrue(out["flags"]["zf"])
        self.assertFalse(out["flags"]["sf"])


if __name__ == '__main__':
    unittest.main()
