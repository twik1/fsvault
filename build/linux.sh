#!/bin/bash
cp ../fsvault.py ./fsvault.pyx
cython fsvault.pyx --embed
gcc -Os -I /usr/include/python3.8/ -o ../fsvault fsvault.c -lpython3.8 -lpthread -lm -lutil -ldl

