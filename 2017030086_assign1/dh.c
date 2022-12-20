#include "dh.h"
#include "util.h"

/*
 * checks the validity of the arguments given by the user
 *
 * arg0: output file path
 * arg1: prime p
 * arg2: primitive root g of p
 * arg3: private a of Alice
 * arg4: private b of Bob
 */
void dh_check_args(char *output_file, int p, int g, int a, int b) {

	if (!output_file) {
		printf("\nError, no output file path.\n\n");
		exit(EXIT_FAILURE);
	}

	if (!is_prime(p)) {
		printf("\nError, p must be a prime number.\n\n");
		exit(EXIT_FAILURE);
	}

	if (!is_primitive_root(p, g)) {
		printf("\nError, g must be a primitive root of p.\n\n");
		exit(EXIT_FAILURE);
	}

	if (a < 1 || a >= p) {
		printf("\nError, private a must be between of 1 and p-1.\n\n");
		exit(EXIT_FAILURE);
	}

	if (b < 1 || a >= p) {
		printf("\nError, private b must be between of 1 and p-1.\n\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * exchanges public keys and produces a shared secret 
 * (based on Diffie-Hellman algorithm)
 * 
 * arg0: output file path
 * arg1: prime p
 * arg2: primitive root g of p
 * arg3: private key a of Alice
 * arg4: private key b of Bob
 */
void dh_key_exchange(char* output_file, int p, int g, int a, int b) {

	int A, B, sa, sb, s;
 	mpz_t p_gmp, g_gmp, a_gmp, b_gmp, A_gmp, B_gmp, sa_gmp, sb_gmp;

    mpz_inits(p_gmp, g_gmp, a_gmp, b_gmp, A_gmp, B_gmp, sa_gmp, sb_gmp, NULL);

	mpz_set_ui(p_gmp, p); 
	mpz_set_ui(g_gmp, g); 
	mpz_set_ui(a_gmp, a);
	mpz_set_ui(b_gmp, b);

	// computing public keys
    mpz_set_ui(A_gmp, A); 
	mpz_set_ui(B_gmp, B);

    mpz_powm(A_gmp, g_gmp, a_gmp, p_gmp);
    A = mpz_get_ui(A_gmp);
    mpz_powm(B_gmp, g_gmp, b_gmp, p_gmp);
    B = mpz_get_ui(B_gmp);

	// computing the shared secret
    mpz_set_ui(sa_gmp, sa); 
	mpz_set_ui(sb_gmp, sb);

    mpz_powm(sa_gmp, B_gmp, a_gmp, p_gmp);
    sa = mpz_get_ui(sa_gmp);
    mpz_powm(sb_gmp, A_gmp, b_gmp, p_gmp);
    sb = mpz_get_ui(sb_gmp);

	mpz_clears(p_gmp, g_gmp, a_gmp, b_gmp, A_gmp, B_gmp, sa_gmp, sb_gmp, NULL);

	// checking if secrets are the same and returning the secret
	s = dh_check_shared_secret(sa, sb);

	printf("\n<%d>, <%d>, <%d>\n\n", A, B, s);

	// writing results in a file
	FILE *wfile;

	wfile = fopen(output_file, "w");
	if (!wfile) {
		printf("\nError, output file path not recognized.\n\n");
		exit(EXIT_FAILURE);
	}
    fprintf(wfile, "<%d>, <%d>, <%d>", A, B, s);
	fclose(wfile);
}

/*
 * checks if the produced secrets are the same and returns the secret
 *
 * arg0: secret of Alice
 * arg1: secret of Bob
 */
int dh_check_shared_secret(int sa, int sb) {

	if (sa != sb) {
		printf("\nDiffie-Hellman secrets share failed.\n\n");
		return -1;
	}

	return sa;
}
