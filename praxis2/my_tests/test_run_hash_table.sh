#!/bin/bash
clang -g -I "../include" ../src/hash_table.c test_hash_table.c -o test
./test

