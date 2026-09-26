#ifndef HB_PE_TLS_H
#define HB_PE_TLS_H

/* Standard PE static TLS directory for this -nodefaultlibs DLL. Include in
 * exactly one translation unit, after Wine's winnt.h declarations. The loader
 * owns per-thread allocation/index publication. This needs no CRT callbacks. */
/* The emulator's ThreadInit precedes Wine's static TLS allocation. An index of
 * zero is valid, so distinguish unpublished state until the loader assigns it. */
DWORD _tls_index = ~(DWORD)0;
static char hb_tls_start __attribute__((section(".tls"), used, aligned(8))) = 0;
static char hb_tls_end __attribute__((section(".tls$ZZZ"), used)) = 0;
const IMAGE_TLS_DIRECTORY64 _tls_used __attribute__((section(".rdata$T"), used)) = {
    (ULONG_PTR)&hb_tls_start,
    (ULONG_PTR)&hb_tls_end,
    (ULONG_PTR)&_tls_index,
    0, /* No TLS callbacks: only plain value storage, no dynamic initialization. */
    0, /* Zero-initialized bytes are already included in the template. */
    0
};

#endif
