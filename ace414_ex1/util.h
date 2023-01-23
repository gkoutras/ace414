#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <gmp.h>

/*
 * checks if a number is prime
 *
 * arg0: number in question
 */
bool is_prime(int);

/*
 * checks if a number is a primimitive root of another number
 *
 * arg0: number base
 * arg1: number in question
 */
bool is_primitive_root(int, int);

/*
 * scans and returns a prime number from user
 *
 * arg0; number of current prime
 * arg1: number of all primes
 */
int scan_prime(int, int);

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
 * prints help info
 */
void dh_help(void);

/*
 * prints help info
 */
void rsa_help(void);

/*
 * prints a note
 */
void note(void);

#endif 