#include "util.h"

/*
 * checks if a number is prime
 *
 * arg0: number in question
 */
bool is_prime(int p) {

	mpz_t p_gmp;
	mpz_init(p_gmp);

	mpz_set_ui(p_gmp, p);

	int i = mpz_probab_prime_p(p_gmp, 50);

	mpz_clear(p_gmp);

	if (i == 2)
		return true;

	return false;
}

/*
 * checks if a number is a primimitive root of another number
 *
 * arg0: number base
 * arg1: number in question
 */
bool is_primitive_root(int p, int g) {

	int i, j;
	double n, m;

	bool is_pr = true;

	i = 0;
	n = 1;

	double *elements = (double *)malloc(sizeof(double) * (p - 2));

	while (n > 0 && i < p - 2) {

		m = pow(g, i);
		n = m - (p * floor(m / p));

		for (j = 0; j < (sizeof(*elements) / sizeof(elements[0])); j++) {

			if (elements[j] == n) {
				free(elements);
				is_pr = false;
				return is_pr;
			}
		}

		elements[i] = n;
		i++;
	}

	free(elements);

	return is_pr;
}

/*
 * scans and returns a prime number from user
 *
 * arg0; number of current prime
 * arg1: number of all primes
 */
int scan_prime(int n, int a) {

	int p;
	
	do {
		printf("Type a prime number (%d/%d): ", n, a);
		scanf("%d", &p);

	} while(!is_prime(p));

	return p;
}

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
 * prints help info
 */
void dh_help(void) {

	printf(
		"\n"
		"Help:\n"
		"\n"
		"Diffie-Hellman Key Exchange Tool\n"
		"The tool will receive the required arguments from the command line upon execution as\n"
		"such:\n"
		"\n"
		"-o path	Path to output file\n"
		"-p number	Prime number\n"
		"-g number	Primitive Root for previous prime number\n"
		"-a number	Private key A\n"
		"-b number	Private key B\n"
		"-h 		This help message\n"
		"\n"
		"The argument -o will be the file name in which the results will be printed.\n"
		"The argument -p will include the will be the public prime number.\n"
		"The argument -g will be the public primitive root of the previous prime number.\n"
		"The argument -a will be the private key of user A.\n"
		"The argument -b will be the private key of user B.\n"
		"\n"
		"The command line tool will return the public key of user A, the public key of user B,\n"
		"and the shared secret. The output will be in the following format:\n"
		"<public key A>, <public key B>, <shared secret>\n"
		"\n"
		"The compiled name of the command line tool is dh_assign_1.\n"
		"\n");

	exit(EXIT_SUCCESS);
}

/*
 * prints help info
 */
void rsa_help(void) {

	printf(
		"\n"
		"Help:\n"
		"\n"
		"RSA Tool\n"
		"The tool will receive the required arguments from the command line upon execution as\n"
		"such:\n"
		"\n"
		"-i path    Path to the input file\n"
		"-o path    Path to the output file\n"
		"-k path    Path to the key file\n"
		"-g         Perform RSA key-pair generation\n"
		"-d         Decrypt input and store results to output\n"
		"-e         Encrypt input and store results to output\n"
		"-h         This help message\n"
		"\n"
		"The arguments \"i\", \"o\" and \"k\" are always required when using \"e\" or \"d\".\n"
		"Using -i and a path the user specifies the path to the input file.\n"
		"Using -o and a path the user specifies the path to the output file.\n"
		"Using -k and a path the user specifies the path to the key file.\n"
		"Using -g the tool generates a public and a private key and\n"
		"stores them to the public.key and private.key files respectively.\n"
		"Using -d the user specifies that the tool should read the ciphertext from the input file,\n"
		"decrypt it and then store the plaintext in the output file.\n"
		"Using -e the user specifies that the tool should read the plaintext from the input file,\n"
		"encrypt it and store the ciphertext in the output file.\n"
		"\n"
		"The compiled name of the command line tool must be rsa_assign_1.\n"
		"\n");

	exit(EXIT_SUCCESS);
}

/*
 * prints a note
 */
void note(void) {

	printf(
		"\n"
		"Two prime numbers needed.\n"
		"*note:	Results depend on these numbers.\n"
		"	If they are too small, the tool might not be successfull\n"
		"	thus, numbers selected are generally large primes.\n"
		"\n");
}
