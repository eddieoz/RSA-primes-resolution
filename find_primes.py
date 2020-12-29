#!/usr/bin/env python

# This tool finds the primes for a given public key and reconstructs the RSA private key
# It uses the method Right Triangle-based Constant time mathematical solution
# explained on robertedwardgrant.com/post/prime-factor-based-encryptions-rendered-useless-by-right-triangle-based-constant-time-solution 
# (with modifications)
#
# Author: Edilson Osorio Jr - @eddieoz - eddieoz.crypto
# License: MIT
# 
# You can generate small keys to test on 
# https://www.mobilefish.com/services/rsa_key_generation/rsa_key_generation.php 
# 
# Usage: $ python3 find_primes.py <hex_pub_key>
# Example: $ python3 find_primes.py b679b3596d04fd

import math
from timeit import default_timer as timer
from random import randrange
import sys

# https://stackoverflow.com/questions/17298130/working-with-large-primes-in-python
# Miller-Rabin
def isPrime(n, k=10):
    if n == 2:
        return True
    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        # x = (a**d) % n
        if x == 1:
            return True
        for i in range(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
            # x = (x**2) % n
        return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range(k):
        a = randrange(2, n - 1)
        if not check(a, s, d, n):
            return False
    return True

# https://gist.github.com/ofaurax/6103869014c246f962ab30a513fb5b49
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

def findSideA(sideB):
    x = int(sideB)
    # x = 0
    
    while(True):
        
        # Calculate r
        r = (x+1) - sideB
        # print a log after 10000000 interations
        if x % 10000000 == 0:
            print('x: %s, r: %s' % (int(x), r))
        
        if r>0:
            # Calculate side A ^ 2 and side A
            # using Pythagorean Factorization Formula: (x+r)*(2B + (x+r)) = Side A^2
            # modified to work (r)*(2B + r) = Side A^2
            sideA2 = (r)*((2*sideB)+(r))
            # Round do adjust te integer if it has a small deviation
            sideA = round(math.sqrt(sideA2),5)
            if sideA.is_integer():       
                # Calculate side C using Pythagorean Theorem
                sideC = round(math.sqrt((sideA**2)+(sideB**2)))
                
                # Calculate the primes p, q
                prime1 = round(sideC + sideA)
                prime2 = round(sideC - sideA)
                if isPrime(prime1) and isPrime(prime2):
                    break
        x+=1
        
    return (sideA, sideC, prime1, prime2)

### Pub keys used in robertedwardgrant.com/post/prime-factor-based-encryptions-rendered-useless-by-right-triangle-based-constant-time-solution
# [15145547, 13053427,236837459, 12193, 52917491789581]
pub_key = 60221408200075953452102
###

# Receive hex_pub_key as a command line parameter 
# Recommended https://www.mobilefish.com/services/rsa_key_generation/rsa_key_generation.php 
# to create a 56bits key
# 
# example: python3 find_primes.py b679b3596d04fd
# hex_pub_key = str(sys.argv[1])
# # convert it to int
# pub_key = int(hex_pub_key,16)

start = timer()
# Calculate the sides A, B and C of the triangle and find the primes p, q
sideB = math.sqrt(pub_key)
sideA, sideC, p, q = findSideA(sideB)
stop = timer()-start

# based on primes found, recalculate the public key
# Modulus (n): n = p * q
modulus = p * q

# Public exponent (e)
e = 65537

# phi(n) = (p - 1) * (q - 1)
phi = (p-1) * (q-1)

# Private exponent (d): d = e ^ -1 mod phi
priv_key = modinv(e, phi)

# print("hex_pub_key: %s int_pub_key: %s\n" % (hex_pub_key, pub_key))
print("Triangle A=%s B=%s C=%s"%(sideA,sideB,sideC))
print("Prime 1 (p): %s Prime2 (q): %s time: %s" % (p,q,stop))
print("exponent e: %s phi(n): %s" % (e, int(phi)))
print("Recovered Public Key modulus (n): %s" % int(modulus))
print("Private Key (d): %s\n" % priv_key)

# Perform an encryption weth the given pub_key and decrypy with the recovered priv_key
message = 159463387759167
print("Message: %s" % message)

# Encrypt Ciphertext (c): c = (m ^ e) mod n
ct = (message**e) % pub_key
ct = pow(message,e,pub_key)
print("Encrypt message with given RSA Public Key: %s" % ct)

# Decrypt (m): m = (c ^ d) mod n
dt = pow(ct, priv_key, modulus)
print("Decrypted message with RSA recovered Private Key: %s " % (dt)) 
 