# ACE414 Assignment 1 

In this assignment, two cryptographic methods were implemented from scratch in C and use of the GMP C library.

- Diffie - Hellman Key Exchange 
- RSA Algorithm

---

## Diffie - Hellman Key Exchange

The generated tool has one function:

- Calculation of the public secret keys of two parties and the jointly calculation their shared secret key.

For this tool, the user has to provide four arguments. The first is a prime number and the second is a primitive root of the previous prime. The third is an integer that represents the private secret of the first party (let's call the party Alice), and the fourth is an integer that represents the private secret of the second party (let's call the party Bob).  

Both parties public secrets are calculated as:

$A = g^{a} mod(p)$ and $B = g^{b} mod(p)$  
where:
- $A$, the public secret of Alice
- $B$, the public secret of Bob
- $p$, a prime
- $g$, a primitive root of $p$
- $a$, the private secret of Alice
- $b$, the private secret of Bob

With these public secrets, the final secret which is shared by both parties, is then calculates as:

$s = B^{a} mod(p)$ or $s = A^{b} mod(p)$  
where:
- $s$, the shared secret of Alice and Bob

This function can be called in the command line by typing:  
`./dh_assign_1 -o <output file path> -p <prime number> -g <primitive root of prime> -a <number> -b <number>`

---

## RSA Algorithm

The generated tool has three functons:

- Generation of a public and a private key, which can be used for encrypting and decrypting a message.
- Encryption of a plain text, using one of the keys, resulting in a cipher text that can't be read.
- Decryption of a cipher text, using the other one of the keys, resulting in a plain text that can be read.

### RSA Key Generation

For the key generation, first the user is asked to provide two prime numbers. These primes will be used to find their product $n$, and Euler's totient function of their product $lambda(n)$. Then a prime number $e$ is selected, so that $e$ and $lamda(n)$ are relative primes, and so their modular inverse $d$ can be calculated correctly. The public key consists of $n, d$, and the private key consists of $n, e$.

*note: Results depend on the prime numbers provided by the user. If they are too small, the tool might not be successfull thus, numbers selected are generally large primes*

This function can be called in the command line by typing:  
`./rsa_assign_1 -g`

### RSA Encryption

For the encryption, the cipher text is calculated as:

$c(p) = p^{k(1)} mod(k(0))$  
where:
- $p$, the plain text input before encryption
- $c(p)$, the cipher text output after ecryption
- $k(1)$, the number $d$ or $e$ (if key is chosen as public or private respectively)
- $k(0)$, the number $n$

This function can be called in the command line by typing:  
`./rsa_assign_1 -e -i <input file path> -o <output file path> -k <key file path>`

### RSA Decryption

For the decryption, the plain text is calculated as:

$p(c) = c^{k(1)} mod(k(0))$  
where:
- $c$, the cipher text input before decryption
- $p(c)$, the plain text output after decryption
- $k(1)$, the number $d$ or $e$ (if key is chosen as public or private respectively)
- $k(0)$, the number $n$

*note: if the public key is selected for encryption, then the private key is the suitable key for decryption and vice versa.*

This function can be called in the command line by typing:  
`./rsa_assign_1 -d -i <input file path> -o <output file path> -k <key file path>`

