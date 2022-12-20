#ifndef _RSA_H
#define _RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <gmp.h>

/*
 * calculates e
 *
 * arg0: lambda(n)
 */
int calculate_e(int, int);

/*
 * calculates d
 *
 * arg0: e
 * arg1: lambda(n)
 */
int calculate_d(int, int);

/*
 * reads plaintext from a file
 *
 * arg0: path to input file
 */
char *read_plaintext(char *);

/*
 * reads ciphertext from a file
 *
 * arg0: path to input file
 */
size_t *read_ciphertext(char *);

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