#include "hash_table.h"
#include <assert.h>
#include <stdio.h>


htable** create_htable() {
	htable** ht = malloc(sizeof(htable*));
	*ht = NULL;
	return ht;
}

htable* item_new(char* key, int key_len, char* value, int value_len) {
	htable* ht = malloc(sizeof(htable));
	ht->value_len = value_len;
	ht->key_len = key_len;
	strncpy((char*) ht->key, key, key_len);
	strncpy((char*) ht->value, value, value_len);
	return ht;
}

void item_free(htable* item) {
	if (item->key != NULL) {
		free(item->key);
	}
	if (item->value != NULL) {
		free(item->value);
	}
	free(item);
}

void assertItem(htable* item, char* key, int key_len, char* val, int val_len) {
	assert(item->key_len == key_len);
	assert(item->value_len == val_len);
	assert(strncmp((char*) item->key, key, key_len) == 0);
	assert(strncmp((char*) item->value, val, val_len) == 0);
}

int main() {
	// setup
	htable** ht = create_htable();
	char key1[] = "key1";
	char key2[] = "key2";
	char key3[] = "key3";
	int key1len = strlen(key1);
	int key2len = strlen(key2);
	int key3len = strlen(key3);
	char val1[] = "val1";
	char val2[] = "val2";
	char val3[] = "val3";
	int val1len = strlen(val1);
	int val2len = strlen(val2);
	int val3len = strlen(val3);

	// test 1
	printf("Test %d \n", 1);
	htable_set(ht, (const unsigned char*) key1, key1len, (const unsigned char*) val1, val1len);
	assertItem(htable_get(ht, (const unsigned char*) key1, key1len), key1, key1len, val1, val1len);
	assert(htable_get(ht, (const unsigned char*) key2, key2len) == NULL);
	assert(htable_get(ht, (const unsigned char*) key3, key3len) == NULL);

	// test 2, add (const unsigned char*) value
	printf("Test %d \n", 2);
	htable_set(ht, (const unsigned char*) key2, key2len, (const unsigned char*) val2, val2len);
	assertItem(htable_get(ht, (const unsigned char*) key1, key1len), key1, key1len, val1, val1len);
	assertItem(htable_get(ht, (const unsigned char*) key2, key2len), key2, key2len, val2, val2len);
	assert(htable_get(ht, (const unsigned char*) key3, key3len) == NULL);

	// test 3, add (const unsigned char*) value
	printf("Test %d \n", 3);
	htable_set(ht, (const unsigned char*) key3, key3len, (const unsigned char*) val3, val3len);
	assertItem(htable_get(ht, (const unsigned char*) key1, key1len), key1, key1len, val1, val1len);
	assertItem(htable_get(ht, (const unsigned char*) key2, key2len), key2, key2len, val2, val2len);
	assertItem(htable_get(ht, (const unsigned char*) key3, key3len), key3, key3len, val3, val3len);

	// test 4, delte (const unsigned char*) value
	printf("Test %d \n", 4);
	htable_delete(ht, (const unsigned char*) key1, key1len);
	assert(htable_get(ht, (const unsigned char*) key1, key1len) == NULL);
	assertItem(htable_get(ht, (const unsigned char*) key2, key2len), key2, key2len, val2, val2len);
	assertItem(htable_get(ht, (const unsigned char*) key3, key3len), key3, key3len, val3, val3len);

	// test 5, set (const unsigned char*) value alread in ht
	printf("Test %d \n", 5);
	htable_set(ht, (const unsigned char*) key3, key3len, (const unsigned char*) val2, val2len);
	assert(htable_get(ht, (const unsigned char*) key1, key1len) == NULL);
	assertItem(htable_get(ht, (const unsigned char*) key2, key2len), key2, key2len, val2, val2len);
	assertItem(htable_get(ht, (const unsigned char*) key3, key3len), key3, key3len, val2, val2len);

	// test 6, set-get 
	printf("Test %d\n", 6);
	const unsigned char key4[] = "Fresh Prince of Bel Air";
	size_t key4len = 23;
	const unsigned char value4[] = "This is a long long long long long long long long long long long text";
	size_t value4len = 69;
	htable_set(ht, key4, key4len, value4, value4len);
	assert(0==strncmp((char*) htable_get(ht, key4, key4len)->value, (char*) value4, value4len));
	
	printf("Done, all tests successfull");
	return 0;
}
