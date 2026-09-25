#!/usr/bin/env python3
"""test_decode.py — decoder tests for x64 MVP subset."""

import unittest
import subprocess
import os
import json


class TestDecodeCLI(unittest.TestCase):
    def setUp(self):
        self.tool = os.path.join(os.path.dirname(__file__), '..', 'tools', 'hb_decode.py')

    def _run(self, arch, hex_str, extra_args=None):
        cmd = ["python3", self.tool, "--arch", arch, "--hex", hex_str, "--json"]
        if extra_args:
            cmd.extend(extra_args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_decode_mov_reg_reg(self):
        """MOV r64, r64: 48 89 C8 = REX.W mov rax, rcx"""
        out = self._run("x64", "4889c8")
        self.assertEqual(out["arch"], "x64")
        self.assertEqual(len(out["instructions"]), 1)
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "MOV")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 8)
        self.assertEqual(insn["op2"]["reg"], 1)
        self.assertEqual(insn["op2"]["size"], 8)

    def test_decode_add_imm8(self):
        """ADD r64, imm8: 48 83 C0 01 = REX.W add rax, 1"""
        out = self._run("x64", "4883c001")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "ADD")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 8)
        self.assertEqual(insn["op2"]["imm"], 1)
        self.assertTrue(insn["writes_flags"])

    def test_decode_push_pop(self):
        """PUSH rax; POP rcx"""
        out = self._run("x64", "5059")
        self.assertEqual(len(out["instructions"]), 2)
        self.assertEqual(out["instructions"][0]["opcode"], "PUSH")
        self.assertEqual(out["instructions"][0]["op1"]["reg"], 0)
        self.assertEqual(out["instructions"][1]["opcode"], "POP")
        self.assertEqual(out["instructions"][1]["op1"]["reg"], 1)

    def test_decode_call_ret(self):
        """CALL rel32; RET"""
        out = self._run("x64", "e805000000c3")
        self.assertEqual(len(out["instructions"]), 2)
        self.assertEqual(out["instructions"][0]["opcode"], "CALL")
        self.assertTrue(out["instructions"][0]["is_call"])
        self.assertEqual(out["instructions"][0]["branch_target"], "0x0000000a")
        self.assertEqual(out["instructions"][1]["opcode"], "RET")
        self.assertTrue(out["instructions"][1]["is_ret"])

    def test_decode_jcc_short(self):
        """JE rel8"""
        out = self._run("x64", "7405")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "Jcc")
        self.assertTrue(insn["is_conditional"])
        self.assertEqual(insn["cond"], "e/z")
        self.assertEqual(insn["branch_target"], "0x00000007")

    def test_decode_mov_mem_disp(self):
        """MOV rax, [rsp+8]"""
        out = self._run("x64", "488b442408")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "MOV")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op2"]["base"], 4)
        self.assertEqual(insn["op2"]["disp"], 8)

    def test_decode_nop(self):
        out = self._run("x64", "90")
        self.assertEqual(out["instructions"][0]["opcode"], "NOP")

    def test_decode_no_input(self):
        result = subprocess.run(
            ["python3", self.tool, "--arch", "x64"],
            capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)

    def test_decode_x86_mov_reg_reg(self):
        """MOV r32, r32: 89 C8 = mov eax, ecx"""
        out = self._run("x86", "89c8")
        self.assertEqual(out["arch"], "x86")
        self.assertEqual(len(out["instructions"]), 1)
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "MOV")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 4)
        self.assertEqual(insn["op2"]["reg"], 1)
        self.assertEqual(insn["op2"]["size"], 4)

    def test_decode_x86_mov_imm32(self):
        """MOV eax, imm32: B8 05 00 00 00 = mov eax, 5"""
        out = self._run("x86", "b805000000")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "MOV")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 4)
        self.assertEqual(insn["op2"]["imm"], 5)

    def test_decode_x86_push_pop(self):
        """PUSH eax; POP ecx"""
        out = self._run("x86", "5059")
        self.assertEqual(len(out["instructions"]), 2)
        self.assertEqual(out["instructions"][0]["opcode"], "PUSH")
        self.assertEqual(out["instructions"][0]["op1"]["reg"], 0)
        self.assertEqual(out["instructions"][1]["opcode"], "POP")
        self.assertEqual(out["instructions"][1]["op1"]["reg"], 1)

    def test_decode_x86_add_imm8(self):
        """ADD eax, imm8: 83 C0 03 = add eax, 3"""
        out = self._run("x86", "83c003")
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "ADD")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op1"]["size"], 4)
        self.assertEqual(insn["op2"]["imm"], 3)
        self.assertTrue(insn["writes_flags"])


class TestDecodeX64EdgeCases(unittest.TestCase):
    def setUp(self):
        self.tool = os.path.join(os.path.dirname(__file__), '..', 'tools', 'hb_decode.py')

    def _run(self, hex_str):
        cmd = ["python3", self.tool, "--arch", "x64", "--hex", hex_str, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_rex_r8_r15(self):
        """REX.B selects r8-r15 in opcode+rd form."""
        out = self._run("4150")  # push r8
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "PUSH")
        self.assertEqual(insn["op1"]["reg"], 8)

    def test_lea_rip_relative(self):
        """LEA rax, [rip+disp32]"""
        out = self._run("488d0500000000")  # lea rax, [rip+0]
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "LEA")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertTrue(insn["op2"]["rip_relative"])

    def test_sub_reg_reg(self):
        """SUB r64, r64"""
        out = self._run("4829c8")  # sub rax, rcx
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "SUB")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op2"]["reg"], 1)

    def test_cmp_imm32(self):
        """CMP r64, imm32"""
        out = self._run("4881f800000000")  # cmp rax, 0
        insn = out["instructions"][0]
        self.assertEqual(insn["opcode"], "CMP")
        self.assertEqual(insn["op1"]["reg"], 0)
        self.assertEqual(insn["op2"]["imm"], 0)


if __name__ == '__main__':
    unittest.main()
