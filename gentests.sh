#!/bin/bash

python parser.py -m -i tests/rot13.c
python parser.py -m -i tests/aes.c
python parser.py -m -i tests/hmac.c
python parser.py -m -i tests/rsa.c
