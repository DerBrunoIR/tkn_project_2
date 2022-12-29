#!/bin/bash
gcc -g -I ../include/ ../src/itoa.c ./test_itoa.c -o ./test 
./test 
