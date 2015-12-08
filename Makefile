# This is a makefile for the provided test cases.
# Generate tests with ./gentests.sh, compile with make and run with make check.

CA_DIR = CA/
TA_DIR = TA/

all:
	make -C $(CA_DIR)ca_hmac
	make -C $(TA_DIR)ta_hmac
	make -C $(CA_DIR)ca_rot13
	make -C $(TA_DIR)ta_rot13
	make -C $(CA_DIR)ca_aes
	make -C $(TA_DIR)ta_aes
	make -C $(CA_DIR)ca_rsa
	make -C $(TA_DIR)ta_rsa

check:
	./bin/hmac
	./bin/aes
	./bin/rsa
	./bin/rot13

clean:
	make clean -C $(CA_DIR)ca_hmac
	make clean -C $(TA_DIR)ta_hmac
	make clean -C $(CA_DIR)ca_rot13
	make clean -C $(TA_DIR)ta_rot13
	make clean -C $(CA_DIR)ca_aes
	make clean -C $(TA_DIR)ta_aes
	make clean -C $(CA_DIR)ca_rsa
	make clean -C $(TA_DIR)ta_rsa
	rm -rf bin/* lib/*
