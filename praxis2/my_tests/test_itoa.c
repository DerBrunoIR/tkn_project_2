#include "itoa.h"
#include <assert.h>

int main() {
	printf("Test reverse\n");
	char* str = calloc(100, sizeof(char)); 
	strcpy(str, "");
	reverse(str);
	assert(0==strcmp(str, ""));

	strcpy(str, "abc");
	reverse(str);
	assert(0==strcmp(str, "cba"));

	strcpy(str, "1234567890");
	reverse(str);
	assert(0==strcmp(str, "0987654321"));
	free(str);

	printf("Test itoa\n");
	str = NULL;
	itoa(&str, 0);
	assert(0==strcmp(str, "0"));
	free(str);

	itoa(&str, -0);
	assert(0==strcmp(str, "0"));
	free(str);

	itoa(&str, -1);
	assert(0==strcmp(str, "-1"));
	free(str);

	itoa(&str, 1);
	assert(0==strcmp(str, "1"));
	free(str);

	itoa(&str, 123456789);
	assert(0==strcmp(str, "123456789"));
	free(str);

	itoa(&str, -123456789);
	assert(0==strcmp(str, "-123456789"));
	free(str);

	itoa(&str, -1000);
	assert(0==strcmp(str, "-1000"));
	free(str);

	itoa(&str, 1000);
	assert(0==strcmp(str, "1000"));
	free(str);
	printf("Test sucessfull");
	return 0;
}
