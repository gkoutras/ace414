#include "rsa.h"

/*
 * calculates e
 *
 * arg0: lambda(n)
 */
int calculate_e(int n, int l) {

	int e, gcd;

	mpz_t l_gmp, e_gmp, gcd_gmp;
	mpz_inits(l_gmp, e_gmp, gcd_gmp, NULL);

	mpz_set_ui(l_gmp, l);

	do
	{
		srand(time(NULL));
		e = rand() % n;
		mpz_set_ui(e_gmp, e);

		mpz_nextprime(e_gmp, e_gmp);
		e = mpz_get_ui(e_gmp);

		mpz_gcd(gcd_gmp, e_gmp, l_gmp);
		gcd = mpz_get_ui(gcd_gmp);

	} while (!(e % l != 0 && gcd == 1 && e < n));

	printf("\n");

	mpz_clears(l_gmp, e_gmp, gcd_gmp, NULL);

	return e;
}

/*
 * calculates d
 *
 * arg0: e
 * arg1: lambda(n)
 */
int calculate_d(int e, int l) {
	int d;

	mpz_t l_gmp, e_gmp, d_gmp;
	mpz_inits(l_gmp, e_gmp, d_gmp, NULL);

	mpz_set_ui(e_gmp, e);
	mpz_set_ui(l_gmp, l);

	mpz_invert(d_gmp, e_gmp, l_gmp);
	d = mpz_get_ui(d_gmp);

	mpz_clears(l_gmp, e_gmp, d_gmp, NULL);

	return d;
}

/*
 * reads plaintext from a file
 *
 * arg0: path to input file
 */
char *read_plaintext(char *file_name) {

	char c;

	unsigned int max_size = 128;
    unsigned int current_size = 0;

	FILE *rfile;

	rfile = fopen(file_name, "r");
	if (!rfile) {
		printf("\nError, input file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}

	char *tmp = (char *)malloc(sizeof(char) * max_size);
	current_size = max_size;

	int i = 0;
	while ((c = fgetc(rfile)) != EOF) {
		
		tmp[i++] = c;

		if (i == current_size) {
			current_size = i + max_size;
			tmp = realloc(tmp, current_size);
		}
	}
	tmp[i] = '\0';

	fclose(rfile);

	return tmp;
}

/*
 * reads ciphertext from a file
 *
 * arg0: path to input file
 */
size_t *read_ciphertext(char *file_name) {

	size_t b;

	unsigned int max_size = 128;
    unsigned int current_size = 0;

	FILE *rfile;

	rfile = fopen(file_name, "r");
	if (!rfile) {
		printf("\nError, input file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}

	size_t *tmp = (size_t *)malloc(sizeof(size_t) * max_size);
	current_size = max_size;

	int i = 0;
	while (fread(&b, sizeof(size_t), 1, rfile) == 1) {
		
		tmp[i++] = b;

		if (i == current_size) {
			current_size = i + max_size;
			tmp = realloc(tmp, current_size);
		}
	}
	tmp[i] = '\0';

	fclose(rfile);

	return tmp;
}

/*
 * generates an RSA key pair and stores each key in a respective file
 */
void rsa_key_generation(void) {

    int p, q;
	int n ,lambda_n, e, d;

	p = 97;
	q = 89;

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
