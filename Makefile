CC=gcc

all: openssl2nettle-rsa

openssl2nettle-rsa: openssl2nettle-rsa.c
	$(CC) openssl2nettle-rsa.c -lcrypto -lnettle -lhogweed -lgmp  -o openssl2nettle-rsa

clean:
	rm -f openssl2nettle-rsa
