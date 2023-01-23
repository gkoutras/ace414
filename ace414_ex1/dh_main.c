#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dh.h"
#include "util.h"

/*
 * parses arguments provided by the user and
 * initiates the key exchange based on Diffie-Hellman algorithm
 */
int main(int argc, char **argv) {

	char *output_file;
	int p, g, a, b;

	// initializing arguments
	output_file = NULL;

	// parsing arguments from command line
	int opt;
	while ((opt = getopt(argc, argv, "o:p:g:a:b:h")) != -1) {
		switch (opt) {
			case 'o':
				output_file = strdup(optarg);
				break;
			case 'p':
				p = atoi(optarg);			
				break;
			case 'g':
				g = atoi(optarg);
				break;
			case 'a':
				a = atoi(optarg);
				break;
			case 'b':
				b = atoi(optarg);
				break;
			case 'h':
				dh_help();
				break;
			default:
				printf("\nError. This argument is not an option. Run again with -h for help.\n\n");
				exit(EXIT_FAILURE);
				break;
		}
	}

	// checking if parsed arguments are valid
	dh_check_args(output_file, p, g, a, b);

	// initiating key exchange 
	dh_key_exchange(output_file, p, g, a, b);

	free(output_file);

	return 0;
}
