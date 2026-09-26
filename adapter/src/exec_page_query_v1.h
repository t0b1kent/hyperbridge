#ifndef WINE_EMULATOR_EXEC_PAGE_QUERY_V1_H
#define WINE_EMULATOR_EXEC_PAGE_QUERY_V1_H

#include <stdint.h>

/* Private, optional NtQueryVirtualMemory class. No syscall ordinal is added.
 * A successful reply describes one logical 4 KiB page at this observation.
 * It is not a permission lease, a host mapping guarantee, or guard consumption.
 * Unsupported or malformed replies require the original BasicInformation path.
 */
#define WINE_EMULATOR_EXEC_PAGE_INFORMATION_CLASS_V1 0x48420001u
#define WINE_EMULATOR_EXEC_PAGE_INFORMATION_VERSION_V1 1u
#define WINE_EMULATOR_EXEC_PAGE_INFORMATION_SIZE_V1 16u
#define WINE_EMULATOR_EXEC_PAGE_SIZE_V1 4096u

typedef struct wine_emulator_exec_page_information_v1
{
    uint32_t size;
    uint32_t version;
    uint32_t state;
    uint32_t protect;
} WINE_EMULATOR_EXEC_PAGE_INFORMATION_V1;

#endif
