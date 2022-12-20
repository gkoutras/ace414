#ifndef _RSA_H
#define _RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

/*
 * checks the validity of the arguments given by the user
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 * arg3: tool operation
 */
void rsa_check_args(char *, char *, char *, int);

/*
 * generates an RSA key pair and stores each key in a respective file
 */
void rsa_key_generation(void);

/*
 * encrypts an input plaintext file into an output ciphertext file
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 */
void rsa_encryption(char *, char *, char *);

/*
 * decrypts an input ciphertext file into an output plaintext file
 *
 * arg0: path to key file
 * arg1: path to input file
 * arg2: path to output file
 */
void rsa_decryption(char *, char *, char *);

#endif 