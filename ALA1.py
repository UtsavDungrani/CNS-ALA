def mod_pow(base, exp, mod):
    """Fast modular exponentiation"""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def gcd_extended(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    g, y, x = gcd_extended(b % a, a)
    return g, x - (b // a) * y, y


def generate_keys(p, q):
    """Generate RSA keys"""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    g, x, _ = gcd_extended(e, phi)
    if g != 1:
        raise ValueError("e and phi not coprime")

    d = x % phi
    return (e, n), (d, n)


# SHA-256 Constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256(message):
    """Pure SHA-256 Implementation"""

    # Initial Hash Values (RESET EVERY TIME)
    H = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    message = bytearray(message)
    bit_len = len(message) * 8

    # Padding
    message.append(0x80)
    while (len(message) % 64) != 56:
        message.append(0)
    message += bit_len.to_bytes(8, 'big')

    # Process each 512-bit chunk
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = list(int.from_bytes(chunk[j:j+4], 'big') for j in range(0, 64, 4))

        for j in range(16, 64):
            s0 = right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = H

        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        H = [(H[j] + val) & 0xFFFFFFFF for j, val in enumerate([a,b,c,d,e,f,g,h])]

    return b''.join(h.to_bytes(4, 'big') for h in H)


def sign_message(message, private_key):
    d, n = private_key
    hash_bytes = sha256(message)
    hash_int = int.from_bytes(hash_bytes, 'big')
    signature = mod_pow(hash_int % n, d, n)  # reduce for demo
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big')


def verify_signature(message, signature, public_key):
    e, n = public_key
    hash_bytes = sha256(message)
    hash_int = int.from_bytes(hash_bytes, 'big')
    sig_int = int.from_bytes(signature, 'big')
    decrypted = mod_pow(sig_int, e, n)
    return decrypted == (hash_int % n)


# ------------------- DEMO -------------------

if __name__ == "__main__":
    p, q = 61, 53   # Small primes for lab demo
    public_key, private_key = generate_keys(p, q)

    print("Public Key:", public_key)
    print("Private Key:", private_key)
    print()

    message = input("Enter message to sign: ").encode()

    signature = sign_message(message, private_key)
    print("Signature (hex):", signature.hex())

    if verify_signature(message, signature, public_key):
        print("Verification: SUCCESS")
    else:
        print("Verification: FAILED")

    print("\n--- Tamper Test ---")
    tampered = input("Enter tampered message: ").encode()

    if tampered == message:
        print("Tampered Verification: SUCCESS")
        print("(No tampering detected – message is unchanged)")
    else:
        if verify_signature(tampered, signature, public_key):
            print("Tampered Verification: SUCCESS (unexpected collision)")
        else:
            print("Tampered Verification: FAILED")
            print("Signature is NOT valid for modified message.")