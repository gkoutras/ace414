#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rsa.h"
#include "util.h"

/*
 * parses arguments provided by the user and
 * initiates the RSA key generation or
 * initiates decryption or
 * initiates encryption
 */
int main(int argc, char **argv) {

    char *key_file, *input_file, *output_file;
	int tool_op;

	// initializing arguments
	key_file = NULL;
	input_file = NULL;
	output_file = NULL;
    tool_op = -1;

	// parsing arguments from command line
	int opt;
	while ((opt = getopt(argc, argv, "i:o:k:gdeh")) != -1) {
		switch (opt) {
			case 'i':
				input_file = strdup(optarg);
				break;
			case 'o':
				output_file = strdup(optarg);
				break;
            case 'k':
				key_file = strdup(optarg);
				break;
            case 'g':
                // selecting RSA key generation
                tool_op = 0;
                break;
            case 'e':
                // selecting RSA encryption
                tool_op = 1;
                break;
            case 'd':
                // selecting RSA decruption
                tool_op = 2;
                break;
			case 'h':
				rsa_help();
				break;
			default:
				printf("\nError. This argument is not an option. Run again with -h for help.\n\n");
				exit(EXIT_FAILURE);
				break;
		}
	}

	// checking if parsed arguments are valid
	rsa_check_args(key_file, input_file, output_file, tool_op);

	// selecting use for the tool
	switch (tool_op) {
		case 0:
			// initiating RSA key generation
			rsa_key_generation();
			break;
		case 1:
			// initiating RSA encryption
			rsa_encryption(key_file, input_file, output_file);
			break;
		case 2:
			// initiating RSA decryption
			rsa_decryption(key_file, input_file, output_file);
			break;
		default:
			break;
	}

	free(key_file);
	free(input_file);
	free(output_file);

	return 0;
}
