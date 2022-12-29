#include "itoa.h"

int reverse(char* str) {
	/* Function: reverse
	 * -----------------
	 *  reverses all characters infront of the delimitor.
	 *  char* str: string
	 *  returns: 0, -1 if str is NULL
	 */
	if (str == NULL)
		return -1;
	int length = strlen(str);
	for (int i = 0; i < length/2; i++) {
		char tmp = str[i];
		str[i] = str[length-i-1];
		str[length-i-1] = tmp;
	}
	return 0;
}

int itoa(char **str_ptr, int num) {
	/* Function: itoa
	 * --------------
	 *  write an integer into the given string.
	 *  char** str_ptr: NULL initialized char* pointer address
	 *  int num: number to convert
	 *  returns: 0
	 */
	// convert num into reversed ascii representation
	int size = 10;
	*str_ptr = malloc(size * sizeof(char));
	char* str = *str_ptr;
	memset(*str_ptr, '\0', size);

	int is_neg = num < 0;
	num = abs(num);
	int i = 0;
	do {
		if (i+1 >= size) {
			size *= 2;
			*str_ptr = realloc(*str_ptr, size * sizeof(char));
			str = *str_ptr;
		}
		int digit = num % 10;
		str[i] = digit + '0';
		num /= 10;
		i++;
	} while (num != 0);
	if (is_neg)
		str[i++] = '-';

	// resize and add eos
	*str_ptr = (char*) realloc(*str_ptr, i * sizeof(char));
	str = *str_ptr;
	str[i] = '\0';

	reverse(*str_ptr);
	return 0;
}
	
