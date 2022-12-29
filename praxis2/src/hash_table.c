#include "hash_table.h"

void htable_free(htable* item) {
	if(item->key)
		free(item->key);
	if(item->value)
		free(item->value);
	free(item);
}

htable* htable_create(const unsigned char *key, size_t key_len, const unsigned char* value, size_t value_len) {
	htable* item = malloc(sizeof(htable));
	item->value = malloc(value_len * sizeof(char));
	item->key = malloc(key_len * sizeof(char));
	strncpy((char*) item->value, (char*) value, value_len);
	strncpy((char*) item->key, (char*) key, key_len);
	item->value_len = value_len;
	item->key_len = key_len;
	return item;
}

void htable_set(htable **ht, const unsigned char *key, size_t key_len,
                const unsigned char *value, size_t value_len) {
	/* TOTEST (Bruno) */
	htable* item = htable_create(key, key_len, value, value_len);
	htable_delete(ht, key, key_len);
	HASH_ADD_KEYPTR(hh, *ht, key, key_len, item);
}

htable *htable_get(htable **ht, const unsigned char *key, size_t key_len) {
	/* TOTEST (Bruno) */
	htable* item = NULL;
	HASH_FIND(hh, *ht, key, key_len, item);
	return item;
}

int htable_delete(htable **ht, const unsigned char *key, size_t key_len) {
    /* TOTEST (Bruno) */
    htable* item = htable_get(ht, key, key_len);
    if (item) {
	HASH_DELETE(hh, *ht, item);
	htable_free(item);
	return 0;
    }
    return -1;
}
