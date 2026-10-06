/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/ldt.h>

static int inspect(unsigned short sel) {
    unsigned ar=0,lim=0; unsigned char ok=0,limok=0;
    __asm__ volatile("lar %2,%0; setz %1" : "=r"(ar),"=qm"(ok) : "r"(sel) : "cc");
    __asm__ volatile("lsl %2,%0; setz %1" : "=r"(lim),"=qm"(limok) : "r"(sel) : "cc");
    printf("selector=%04x LAR_valid=%u",sel,ok);
    if(ok) printf(" access=%08x code=%u dpl=%u present=%u long=%u default32=%u",ar,(ar>>11)&1,(ar>>13)&3,(ar>>15)&1,(ar>>21)&1,(ar>>22)&1);
    printf(" LSL_valid=%u",limok); if(limok) printf(" limit=%08x",lim); putchar('\n');
    return ok && ((ar>>11)&1) && (((ar>>13)&3)==3) && ((ar>>15)&1) && !((ar>>21)&1) && ((ar>>22)&1);
}
int main(void) {
    unsigned short cs,ds,ss,fs,gs;
    __asm__ volatile("mov %%cs,%0; mov %%ds,%1; mov %%ss,%2" : "=r"(cs),"=r"(ds),"=r"(ss));
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1" : "=r"(fs),"=r"(gs));
    printf("current_CS=%04x current_DS=%04x current_SS=%04x current_FS=%04x current_GS=%04x\n",cs,ds,ss,fs,gs);
    int available=inspect(0x23);
    if(available) { puts("READY: existing user 32-bit code selector 0023"); return 0; }
    puts("Existing candidate 0023 is not a present user 32-bit code descriptor; trying normal per-process modify_ldt once.");
    struct user_desc desc={0}; desc.entry_number=0; desc.base_addr=0; desc.limit=0xfffff;
    desc.seg_32bit=1; desc.contents=2; desc.read_exec_only=0; desc.limit_in_pages=1;
    desc.seg_not_present=0; desc.useable=1;
    errno=0; long rc=syscall(SYS_modify_ldt,1,&desc,sizeof desc); int saved=errno;
    printf("modify_ldt(function=1, entry=0, code32, base=0, limit=4GiB) return=%ld errno=%d (%s)\n",rc,saved,strerror(saved));
    if(rc<0) { puts("UNAVAILABLE: no retries, privilege changes, or alternative routes after syscall denial."); return 77; }
    available=inspect(0x7);
    puts(available ? "READY: per-process LDT user 32-bit code selector 0007" : "UNAVAILABLE: created descriptor not usable as user 32-bit code");
    return available?0:77;
}
