#include "rsa.h"
#include "util.h"

/*
 * checks the validity of the arguments given by the user
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 * arg3: tool operation
 */
void rsa_check_args(char *key_file, char *input_file, char *output_file, int tool_op) {

	if (!key_file && tool_op != 0) {
		printf("\nError, no key file path.\n\n");
		exit(EXIT_FAILURE);
	}

    if (!input_file && tool_op != 0) {
		printf("\nError, no input file path given.\n\n");
		exit(EXIT_FAILURE);
	}

	if (!output_file && tool_op != 0) {
		printf("\nError, no output file path given.\n\n");
		exit(EXIT_FAILURE);
	}

    if (tool_op == -1) {
		printf("Error, no operation selected for the tool.\n\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * generates an RSA key pair and stores each key in a respective file
 */
void rsa_key_generation(void) {

    int p, q;
	int n ,lambda_n, e, d;

	note();

    // scanning primes p and q from user
	p = scan_prime(1, 2);
	q = scan_prime(2, 2);

    // calculating n and lambda(n)
    n = p * q;
	lambda_n = (p - 1) * (q - 1);

    // selecting a suitable e
	e = calculate_e(n, lambda_n);
	
    // calculating the modular inverse d of e and lambda(n)
	d = calculate_d(e, lambda_n);

	size_t public_key[2] = {n, d};
	size_t private_key[2] = {n, e};

    // writing public and private keys in respective key files
    FILE *wfile;

	wfile = fopen("public.key", "w");
	fwrite(public_key, sizeof(size_t), 2, wfile);
	fclose(wfile);

	wfile = fopen("private.key", "w");
	fwrite(private_key, sizeof(size_t), 2, wfile);
	fclose(wfile);
}

/*
 * encrypts an input plaintext file into an output ciphertext file
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 */
void rsa_encryption(char *key_file, char *input_file, char *output_file) {

	char *plaintext;
	
	size_t *key = (size_t *)malloc(sizeof(size_t) * 2);

	// reading public key from key file
	FILE *rfile;

	rfile = fopen(key_file, "r");
	if (!rfile) {
		printf("\nError, key file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}
	fread(key, sizeof(size_t), 2, rfile);
	fclose(rfile);

	// reading plaintext from input file
	plaintext = read_plaintext(input_file);

	size_t *ciphertext = (size_t *)malloc(sizeof(size_t) * strlen(plaintext));

	mpz_t k0_gmp, k1_gmp, pt_gmp, ct_gmp;
	mpz_inits(k0_gmp, k1_gmp, pt_gmp, ct_gmp, NULL);

	mpz_set_si(k0_gmp, key[0]);
	mpz_set_si(k1_gmp, key[1]);

	// calculating the encryption of plaintext to ciphertext
	int i;
	for (i = 0; i < strlen(plaintext); i++) {

		mpz_set_si(pt_gmp, (size_t)plaintext[i]);

		mpz_powm(ct_gmp, pt_gmp, k1_gmp, k0_gmp);
		ciphertext[i] = (size_t)mpz_get_si(ct_gmp);
	}

	mpz_clears(k0_gmp, k1_gmp, pt_gmp, ct_gmp, NULL);

	// writing ciphertext to output file
	FILE *wfile;

	wfile = fopen(output_file, "w");
    if (!wfile) {
		printf("\nError, output file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}

    fwrite(ciphertext, sizeof(size_t), strlen(plaintext), wfile);
	fclose(wfile);

	free(key);
	free(ciphertext);
}

/*
 * decrypts an input ciphertext file into an output plaintext file
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 */
void rsa_decryption(char *key_file, char *input_file, char *output_file) {

	size_t *ciphertext;
	
	size_t *key = (size_t *)malloc(sizeof(size_t) * 2);

	// reading public key from key file
	FILE *rfile;

	rfile = fopen(key_file, "r");
	if (!rfile) {
		printf("\nError, key file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}
	fread(key, sizeof(size_t), 2, rfile);
	fclose(rfile);

	// reading ciphertext from input file
	ciphertext = read_ciphertext(input_file);
	size_t *ct = ciphertext;

	int len_ciphertext = 0;
	while (*ct != '\0') {
		len_ciphertext++;
		ct++;
	}

	char *plaintext = (char *)malloc(sizeof(char) * len_ciphertext);

	mpz_t k0_gmp, k1_gmp, pt_gmp, ct_gmp;
	mpz_inits(k0_gmp, k1_gmp, pt_gmp, ct_gmp, NULL);

	mpz_set_si(k0_gmp, key[0]);
	mpz_set_si(k1_gmp, key[1]);

	// calculating the decryption of ciphertext to plaintext
	int i;
	for (i = 0; i < len_ciphertext; i++) {

		mpz_set_si(ct_gmp, (size_t)ciphertext[i]);

		mpz_powm(pt_gmp, ct_gmp, k1_gmp, k0_gmp);
		plaintext[i] = (char)mpz_get_si(pt_gmp);
	}

	mpz_clears(k0_gmp, k1_gmp, pt_gmp, ct_gmp, NULL);

	// writing plaintext to output file
	FILE *wfile;

	wfile = fopen(output_file, "w");
    if (!wfile) {
		printf("\nError, output file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}

    fputs(plaintext, wfile);
	fclose(wfile);

	free(key);
	free(plaintext);
}