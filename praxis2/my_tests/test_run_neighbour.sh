#!/bin/bash
clang -g -I "../include" ../src/neighbour.c test_neighbour.c -o test
./test
rm test

