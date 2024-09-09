import math
import sys
from timeit import default_timer as timer
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Activation
from tensorflow.keras.optimizers import Adam


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
        a = np.random.randint(2, n)
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

def find_primes(pub_key):
    model = Sequential()
    model.add(Dense(64, input_dim=1, activation='relu'))
    model.add(Dense(32, activation='relu'))
    model.add(Dense(16, activation='relu'))
    model.add(Dense(2, activation='linear'))
    model.compile(loss='mse', optimizer=Adam())

    X_train = np.array([pub_key])
    y_train = np.array([[0, 0]])
    model.fit(X_train, y_train, epochs=1000, batch_size=1, verbose=0)

    primes = model.predict(X_train)[0]
    p, q = round(primes[0]), round(primes[1])

    if is_prime(p) and is_prime(q):
        return p, q
    else:
        raise ValueError("Failed to find primes")

def main():
    hex_pub_key = str(sys.argv[1])
    pub_key = int(hex_pub_key, 16)

    start = timer()
    p, q = find_primes(pub_key)
    stop = timer() - start

    modulus = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    priv_key = modinv(e, phi)

    print("hex_pub_key: %s int_pub_key: %s" % (hex_pub_key, pub_key))
    print("Prime 1 (p): %s Prime2 (q): %s time: %s" % (p, q, stop))
    print("exponent e: %s phi(n): %s" % (e, int(phi)))
    print("Recovered Public Key modulus (n): %s" % int(modulus))
    print("Private Key (d): %s" % priv_key)

    message = 159463387759167
    print("Message: %s" % message)

    ct = pow(message, e, pub_key)
    print("Encrypt message with given RSA Public Key: %s" % ct)

    dt = pow(ct, priv_key, modulus)
    print("Decrypted message with RSA recovered Private Key: %s" % dt)

if __name__ == "__main__":
    main()
