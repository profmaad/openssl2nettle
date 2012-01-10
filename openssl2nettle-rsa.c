# include <stdio.h>
# include <stdlib.h>

# include <openssl/pem.h>
# include <openssl/rsa.h>
# include <openssl/bn.h>
# include <openssl/err.h>
# include <openssl/evp.h>

# include <nettle/rsa.h>
# include <nettle/buffer.h>

# include <gmp.h>

//# define DEBUG

int main(int argc, char **argv)
{
	FILE *input = stdin;

	RSA *openssl_key = NULL;
	struct rsa_private_key *nettle_key = NULL;
	struct rsa_public_key *nettle_pub_key = NULL;
	struct nettle_buffer *sexp_buffer = NULL;

	OpenSSL_add_all_algorithms();
	
	openssl_key = PEM_read_RSAPrivateKey(input, NULL, NULL, NULL);

	if(!openssl_key)
	{
		fprintf(stderr, "OpenSSL failed to read key: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

# ifdef DEBUG
	fprintf(stderr, "OpenSSL RSA private key:\n");
	fprintf(stderr, "\tPrivate Exponent: %s\n", BN_bn2hex(openssl_key->d)); // d
	fprintf(stderr, "\tPrime 1: %s\n", BN_bn2hex(openssl_key->p));          // p
	fprintf(stderr, "\tPrime 2: %s\n", BN_bn2hex(openssl_key->q));          // q
	fprintf(stderr, "\tExponent 1: %s\n", BN_bn2hex(openssl_key->dmp1));    // a
	fprintf(stderr, "\tExponent 2: %s\n", BN_bn2hex(openssl_key->dmq1));    // b
	fprintf(stderr, "\tCoefficient: %s\n", BN_bn2hex(openssl_key->iqmp));   // c
# endif

	nettle_key = (struct rsa_private_key*)malloc(sizeof(struct rsa_private_key));
	if(!nettle_key)
	{
		fprintf(stderr, "Failed to malloc %zu bytes\n", sizeof(struct rsa_private_key));
		return 4;
	}
	rsa_private_key_init(nettle_key);
	mpz_set_str(nettle_key->d, BN_bn2hex(openssl_key->d), 16);
	mpz_set_str(nettle_key->p, BN_bn2hex(openssl_key->p), 16);
	mpz_set_str(nettle_key->q, BN_bn2hex(openssl_key->q), 16);
	mpz_set_str(nettle_key->a, BN_bn2hex(openssl_key->dmp1), 16);
	mpz_set_str(nettle_key->b, BN_bn2hex(openssl_key->dmq1), 16);
	mpz_set_str(nettle_key->c, BN_bn2hex(openssl_key->iqmp), 16);

	if(rsa_private_key_prepare(nettle_key) != 1)
	{
		fprintf(stderr, "Nettle failed to prepare key\n");
		return 2;
	}

# ifdef DEBUG
	fprintf(stderr, "\tPrivate Exponent: %s\n", mpz_get_str(NULL, 16, nettle_key->d)); // d
	fprintf(stderr, "\tPrime 1: %s\n", mpz_get_str(NULL, 16, nettle_key->p));          // p
	fprintf(stderr, "\tPrime 2: %s\n", mpz_get_str(NULL, 16, nettle_key->q));          // q
	fprintf(stderr, "\tExponent 1: %s\n", mpz_get_str(NULL, 16, nettle_key->a));    // a
	fprintf(stderr, "\tExponent 2: %s\n", mpz_get_str(NULL, 16, nettle_key->b));    // b
	fprintf(stderr, "\tCoefficient: %s\n", mpz_get_str(NULL, 16, nettle_key->c));   // c
# endif

	nettle_pub_key = (struct rsa_public_key*)malloc(sizeof(struct rsa_public_key));
	if(!nettle_pub_key)
	{
		fprintf(stderr, "Failed to malloc %zu bytes\n", sizeof(struct rsa_public_key));
		return 4;
	}
	rsa_public_key_init(nettle_pub_key);
	mpz_set_str(nettle_pub_key->n, BN_bn2hex(openssl_key->n), 16);
	mpz_set_str(nettle_pub_key->e, BN_bn2hex(openssl_key->e), 16);
	
	if(rsa_public_key_prepare(nettle_pub_key) != 1)
	{
		fprintf(stderr, "Nettle failed to prepare public key\n");
		return 2;
	}

	sexp_buffer = (struct nettle_buffer*)malloc(sizeof(struct nettle_buffer));
	if(!sexp_buffer)
	{
		fprintf(stderr, "Failed to malloc %zu bytes\n", sizeof(struct nettle_buffer));
		return 4;
	}
	nettle_buffer_init(sexp_buffer);

	if(rsa_keypair_to_sexp(sexp_buffer, NULL, nettle_pub_key, nettle_key) == 0)
	{
		fprintf(stderr, "Nettle failed to export key to sexp\n");
		return 3;
	}

	size_t bytes_written = fwrite(sexp_buffer->contents, 1, sexp_buffer->size, stdout);
	if(bytes_written < sexp_buffer->size)
	{
		fprintf(stderr, "Failed to write sexp to stdout\n");
		return 5;
	}

	return 0;
}
