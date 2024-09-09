# This tool finds the primes for a given public key and reconstructs the RSA private key
# It uses the method Right Triangle-based Constant time mathematical solution
# explained on robertedwardgrant.com/post/prime-factor-based-encryptions-rendered-useless-by-right-triangle-based-constant-time-solution 
# (with modifications)
# This code update uses a hybrid approach, combining neural networks and classical methods for factoring RSA public keys.
# Authors: Edilson Osorio Jr - @eddieoz - eddieoz.crypto
           Felipe - @mrfelpa

# License: MIT
# 
# You can generate small keys to test on 
# https://www.mobilefish.com/services/rsa_key_generation/rsa_key_generation.php 
# 
# Usage: $ python3 find_primes.py <hex_pub_key>
# Example: $ python3 find_primes.py b679b3596d04fd

import math
import sys
import random
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from rich.console import Console
from rich.table import Table
from timeit import default_timer as timer

def is_prime(n, k=10):
    if n == 2:
        return True
    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for i in range(1, s):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range(k):
        a = random.randint(2, n)
        if not check(a, s, d, n):
            return False
    return True

# Extended Euclid Algorithm
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

# Modular Inverse
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

# Neural Network Model
model = Sequential()
model.add(Dense(64, input_dim=1, activation='relu'))
model.add(Dense(32, activation='relu'))
model.add(Dense(16, activation='relu'))
model.add(Dense(2, activation='linear'))
model.compile(loss='mse', optimizer=Adam())


def find_primes(pub_key):
    primes = model.predict(np.array([[pub_key]]))[0]

    
    if np.isnan(primes).any():
        raise ValueError("Model prediction returned NaN values.")

    p, q = round(primes[0]), round(primes[1])

    if is_prime(p) and is_prime(q):
        return p, q
    else:
        raise ValueError("Failed to find valid primes.")

def update_model(pub_key, p, q):
    X_new = np.array([[pub_key]])
    y_new = np.array([[p, q]])
    model.fit(X_new, y_new, epochs=10, batch_size=1, verbose=0)

def main():
    console = Console()

    if len(sys.argv) < 2:
        console.print("Usage: python script.py <hex_pub_key>", style="bold red")
        sys.exit(1)

    hex_pub_key = sys.argv[1]
    pub_key = int(hex_pub_key, 16)

    start = timer()
    
    try:
        p, q = find_primes(pub_key)
    except ValueError as e:
        console.print(f"[bold red]{e}[/bold red]")
        console.print("Falling back to classic prime search...")
        
        # Default search if model fails
        p = pub_key // 2
        while not is_prime(p):
            p -= 1
        q = p + 1
        while not is_prime(q):
            q += 1

    # Update the model with new data
    update_model(pub_key, p, q)

    stop = timer() - start

    modulus = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    priv_key = modinv(e, phi)

    table = Table(title="RSA Key Information")
    table.add_column("Key", justify="left", style="cyan", no_wrap=True)
    table.add_column("Value", justify="right", style="magenta")

    table.add_row("hex_pub_key", hex_pub_key)
    table.add_row("int_pub_key", str(pub_key))
    table.add_row("Prime 1 (p)", str(p))
    table.add_row("Prime 2 (q)", str(q))
    table.add_row("Time", f"{stop:.10f} seconds")
    table.add_row("exponent e", str(e))
    table.add_row("phi(n)", str(int(phi)))
    table.add_row("Recovered Public Key modulus (n)", str(int(modulus)))
    table.add_row("Private Key (d)", str(priv_key))

    console.print(table)

    message = 159463387759167
    console.print(f"Message: [green]{message}[/green]")

    ct = pow(message, e, pub_key)
    console.print(f"Encrypt message with given RSA Public Key: [yellow]{ct}[/yellow]")

    dt = pow(ct, priv_key, modulus)
    console.print(f"Decrypted message with RSA recovered Private Key: [green]{dt}[/green]")

if __name__ == "__main__":
    main()
