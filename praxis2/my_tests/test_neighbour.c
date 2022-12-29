#include <stdio.h>
#include <assert.h>
#include "neighbour.h"

// int peer_is_responsible(uint16_t pred_id, uint16_t peer_id, uint16_t hash_id);


int main() {
	// test 1, is responsible
	printf("test %d\n", 1);
	assert(peer_is_responsible(10, 50, 45) == 1);
	assert(peer_is_responsible(10, 50, 50) == 1);
	assert(peer_is_responsible(10, 50, 11) == 1);
	// test 2, is not responsible
	printf("test %d\n", 2);
	assert(peer_is_responsible(10, 50, 10) == 0);
	assert(peer_is_responsible(10, 50,  9) == 0);
	assert(peer_is_responsible(10, 50, 51) == 0);
	// test 3, is responsible around zero
	printf("test %d\n", 3);
	assert(peer_is_responsible(UINT16_MAX-5, 50, 50) == 1);
	assert(peer_is_responsible(UINT16_MAX-5, 50,  0) == 1);
	assert(peer_is_responsible(UINT16_MAX-5, 50, UINT16_MAX-4) == 1);
	// test 4, is not responsible around zero
	printf("test %d\n", 4);
	assert(peer_is_responsible(UINT16_MAX-5, 50,  51) == 0);
	assert(peer_is_responsible(UINT16_MAX-5, 50,  123) == 0);
	assert(peer_is_responsible(UINT16_MAX-5, 50, UINT16_MAX-5) == 0);
	// test 5, special cases
	printf("test %d\n", 5);
	assert(peer_is_responsible(1, 10, 2000) == 0);
	assert(peer_is_responsible(10, 1025, 2000) == 0);


	printf("all tests successfully");
}

