/* Наблюдение разделения арм по версии ключа постоянного кеша (лейн РЕГИСТРЫ, итерация 23). */
#include "hb_runtime.h"
#include <stdio.h>
int main(void) { printf("%u\n", hb_runtime_persistent_cache_version()); return 0; }
