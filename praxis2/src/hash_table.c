#include "hash_table.h"

void htable_set(htable **ht, const unsigned char *key, size_t key_len,
                const unsigned char *value, size_t value_len) {
    /* TODO IMPLEMENT */
}

htable *htable_get(htable **ht, const unsigned char *key, size_t key_len) {
    /* TODO IMPLEMENT */
    // return NULL on error
    return NULL;
}

int htable_delete(htable **ht, const unsigned char *key, size_t key_len) {
    /* TODO IMPLEMENT */
    // return -1 on error
    htable* item = malloc(sizeof(htable));
    HASH_FIND(hh, *ht, key, key_len , item);
    return -1;
}
