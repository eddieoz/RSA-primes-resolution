# This tool finds the primes for a given public key and reconstructs the RSA private key
# It uses the method Right Triangle-based Constant time mathematical solution
# explained on robertedwardgrant.com/post/prime-factor-based-encryptions-rendered-useless-by-right-triangle-based-constant-time-solution 
# (with modifications)
# This code update uses a hybrid approach, combining neural networks and classical methods for factoring RSA public keys.
# Authors: Edilson Osorio Jr - @eddieoz - eddieoz.crypto
           @Alb4don

# License: MIT
# 
# You can generate small keys to test on 
# https://www.mobilefish.com/services/rsa_key_generation/rsa_key_generation.php 
# 
# Usage: $ python3 find_primes.py <hex_pub_key>
# Example: $ python3 find_primes.py b679b3596d04fd

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import math
import sys
import random
import numpy as np
import tensorflow as tf
tf.get_logger().setLevel('ERROR')
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.optimizers import Adam
from rich.console import Console
from rich.table import Table
from timeit import default_timer as timer
import json
import argparse
from multiprocessing import Pool, cpu_count
import warnings
warnings.filterwarnings('ignore')

def is_prime(n, k=40):
    if n == 2 or n == 3:
        return True
    if n < 2 or not n & 1:
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
        a = random.randrange(2, n)
        if not check(a, s, d, n):
            return False
    return True

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

def rho_attempt(args):
    n, c = args
    x = 2
    y = 2
    d = 1
    iter_count = 0
    max_iter = 1000000
    while d == 1 and iter_count < max_iter:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        iter_count += 2
    if d == 1 or d == n:
        return None
    return d

def factor_with_rho(n):
    if n < 2:
        raise ValueError("Invalid n")
    if is_prime(n):
        raise ValueError("n is prime")
    if n % 2 == 0:
        return 2, n // 2
    sqrt_n = int(math.sqrt(n)) + 1
    for i in range(3, min(10000, sqrt_n + 1), 2):
        if n % i == 0:
            return i, n // i
    num_processes = cpu_count()
    max_attempts = num_processes * 10
    with Pool(num_processes) as pool:
        cs = [random.randint(1, n - 1) for _ in range(max_attempts)]
        args_list = [(n, c) for c in cs]
        results = pool.map(rho_attempt, args_list)
        for d in results:
            if d is not None and 1 < d < n:
                p = min(d, n // d)
                q = max(d, n // d)
                if is_prime(p) and is_prime(q):
                    return p, q
    raise ValueError("Failed to factor n")

model = Sequential([
    Input(shape=(1,)),
    Dense(64, activation='relu'),
    Dense(32, activation='relu'),
    Dense(16, activation='relu'),
    Dense(2, activation='linear')
])
model.compile(loss='mse', optimizer=Adam(learning_rate=0.001))

def load_data_and_model(data_file, model_file):
    data = []
    try:
        with open(data_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        pass
    loaded_model = model
    try:
        loaded_model = tf.keras.models.load_model(model_file)
    except Exception:
        pass
    return data, loaded_model

def save_data(data, data_file):
    with open(data_file, 'w') as f:
        json.dump(data, f)

def update_model_and_data(pub_key, p, q, data, model, data_file, model_file):
    if pub_key < (1 << 53) and str(pub_key) not in [d['n'] for d in data]:
        data.append({"n": str(pub_key), "p": str(p), "q": str(q)})
        save_data(data, data_file)
        small_data = [d for d in data if int(d['n']) < (1 << 53)]
        if len(small_data) > 0:
            X = np.array([[float(d['n'])] for d in small_data])
            y = np.array([[float(d['p']), float(d['q'])] for d in small_data])
            model.fit(X, y, epochs=50, batch_size=min(32, len(small_data)), verbose=0)
            model.save(model_file)

def find_primes(pub_key, model, data_file, model_file):
    if pub_key < (1 << 53):
        try:
            X_new = np.array([[float(pub_key)]])
            primes = model.predict(X_new, verbose=0)[0]
            p_est = round(primes[0])
            q_est = round(primes[1])
            if p_est > 1 and q_est > 1 and p_est * q_est == pub_key and is_prime(p_est) and is_prime(q_est):
                return sorted([p_est, q_est])
        except:
            pass
    return factor_with_rho(pub_key)

def main():
    parser = argparse.ArgumentParser(description='RSA Key Factorizer')
    parser.add_argument('hex_pub_key', type=str, help='Hexadecimal public key modulus')
    parser.add_argument('--data-file', type=str, default='rsa_data.json', help='Data file for training')
    parser.add_argument('--model-file', type=str, default='model.h5', help='Model file')
    args = parser.parse_args()

    try:
        pub_key = int(args.hex_pub_key, 16)
    except ValueError:
        Console().print("Invalid hexadecimal public key", style="bold red")
        sys.exit(1)

    if pub_key < 2:
        Console().print("Public key must be greater than 1", style="bold red")
        sys.exit(1)

    console = Console()
    data, model = load_data_and_model(args.data_file, args.model_file)

    start = timer()
    try:
        p, q = find_primes(pub_key, model, args.data_file, args.model_file)
    except ValueError as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)

    update_model_and_data(pub_key, p, q, data, model, args.data_file, args.model_file)

    stop = timer() - start
    e = 65537
    phi = (p - 1) * (q - 1)
    priv_key = modinv(e, phi)
    modulus = pub_key

    table = Table(title="RSA Key Information")
    table.add_column("Key", justify="left", style="cyan", no_wrap=True)
    table.add_column("Value", justify="right", style="magenta")
    table.add_row("hex_pub_key", args.hex_pub_key)
    table.add_row("int_pub_key", str(pub_key))
    table.add_row("Prime 1 (p)", str(p))
    table.add_row("Prime 2 (q)", str(q))
    table.add_row("Time", f"{stop:.10f} seconds")
    table.add_row("exponent e", str(e))
    table.add_row("phi(n)", str(phi))
    table.add_row("Public Key modulus (n)", str(modulus))
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

    dt = pow(ct, priv_key, modulus)
    console.print(f"Decrypted message with RSA recovered Private Key: [green]{dt}[/green]")

if __name__ == "__main__":
    main()
