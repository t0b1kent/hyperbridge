#ifndef XTAJIT64_X87_H
#define XTAJIT64_X87_H

#include "xtajit64_exec.h"
#include "hb_x87_wire.h"

/* Append only. V1 through V5 packets and every previous ordinal are unchanged. */
enum xtajit64_unix_funcs_x87
{
    unix_x87_transfer = unix_funcs_count_v5,
    unix_funcs_count_x87
};
#define XTAJIT64_FEATURE_X87_TRANSFER 0x10u

static inline int xtajit64_process_init_supports_x87( const struct xtajit64_process_init_params *params )
{
    return xtajit64_process_init_supports_v5( params ) &&
           (params->features & XTAJIT64_FEATURE_X87_TRANSFER) &&
           params->unix_funcs_count > unix_x87_transfer;
}

C_ASSERT(unix_x87_transfer == 15);
C_ASSERT(unix_funcs_count_x87 == 16);
#endif
