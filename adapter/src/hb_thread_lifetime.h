/* Independent host-thread ownership for the Unix emulator resources.
 * Wine's ThreadTerm / ProcessTerm exports are PRE notifications: neither is
 * an ownership boundary. In particular, they may run on a surviving caller.
 * Actual host-thread exit owns teardown through a pthread key destructor.
 */
#ifndef HB_THREAD_LIFETIME_H
#define HB_THREAD_LIFETIME_H

#include <pthread.h>
#include <stdlib.h>
#include "hb_context.h"
#include "hb_memory.h"
#include "hb_runtime.h"

struct hb_thread_resources
{
    hb_context_t *ctx;
    hb_jit_runtime_t *jit;
};

static pthread_key_t hb_thread_resources_key;
static pthread_once_t hb_thread_resources_once = PTHREAD_ONCE_INIT;
static int hb_thread_resources_key_error;

static void hb_thread_resources_destroy(void *value)
{
    struct hb_thread_resources *resources = value;
    if (!resources) return;
    if (resources->jit) hb_jit_runtime_destroy(resources->jit);
    if (resources->ctx)
    {
        /* The address-space object is shared and lives until process exit. */
        resources->ctx->memory = NULL;
        hb_context_destroy(resources->ctx);
    }
    free(resources);
}

static void hb_thread_resources_create_key(void)
{
    hb_thread_resources_key_error = pthread_key_create(&hb_thread_resources_key,
                                                       hb_thread_resources_destroy);
}

/* NULL means nothing was published. Failure to create a JIT keeps the existing
 * interpreter fallback. Failure to register ownership rolls back both objects.
 * The containing Unix module must remain loaded while emulator threads exist.
 */
static struct hb_thread_resources *hb_thread_resources_get(hb_memory_t *memory, int use_jit)
{
    struct hb_thread_resources *resources;
    if (pthread_once(&hb_thread_resources_once, hb_thread_resources_create_key) ||
        hb_thread_resources_key_error) return NULL;
    resources = pthread_getspecific(hb_thread_resources_key);
    if (resources) return resources;
    resources = calloc(1, sizeof(*resources));
    if (!resources) return NULL;
    resources->ctx = hb_context_create(HB_ARCH_X64, use_jit ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
    if (!resources->ctx)
    {
        free(resources);
        return NULL;
    }
    resources->ctx->memory = memory;
    if (use_jit) resources->jit = hb_jit_runtime_create(resources->ctx);
    if (pthread_setspecific(hb_thread_resources_key, resources))
    {
        hb_thread_resources_destroy(resources);
        return NULL;
    }
    return resources;
}

#endif
