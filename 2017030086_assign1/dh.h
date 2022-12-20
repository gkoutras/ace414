#ifndef _DH_H
#define _DH_H

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

/*
 * checks the validity of the arguments given by the user
 *
 * arg0: output file path
 * arg1: prime p
 * arg2: primitive root g of p
 * arg3: private a of Alice
 * arg4: private b of Bob
 */
void dh_check_args(char *, int, int, int, int);

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
void dh_key_exchange(char*, int, int, int, int);

/*
 * checks if the produced secrets are the same and returns the secret
 *
 * arg0: secret of Alice
 * arg1: secret of Bob
 */
int dh_check_shared_secret(int, int);

#endif 
