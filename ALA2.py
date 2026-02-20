def right_rotate(x, n, bits=32):
    return ((x >> n) | (x << (bits - n))) & ((1 << bits) - 1)


# ========================= SHA-1 =========================

def sha1(message):

    message = bytearray(message.encode())
    bit_len = len(message) * 8

    message.append(0x80)
    while (len(message) % 64) != 56:
        message.append(0)
    message += bit_len.to_bytes(8, 'big')

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = list(int.from_bytes(chunk[j:j+4], 'big') for j in range(0, 64, 4))

        for j in range(16, 80):
            val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w.append(right_rotate(val, 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if 0 <= j < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (right_rotate(a, 27) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = right_rotate(b, 2)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return ''.join(format(x, '08x') for x in [h0, h1, h2, h3, h4])


# ========================= SHA-256 =========================

K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def sha256(message):

    message = bytearray(message.encode())
    bit_len = len(message) * 8

    message.append(0x80)
    while (len(message) % 64) != 56:
        message.append(0)
    message += bit_len.to_bytes(8, 'big')

    H = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ]

    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = list(int.from_bytes(chunk[j:j+4],'big') for j in range(0,64,4))

        for j in range(16,64):
            s0 = right_rotate(w[j-15],7)^right_rotate(w[j-15],18)^(w[j-15]>>3)
            s1 = right_rotate(w[j-2],17)^right_rotate(w[j-2],19)^(w[j-2]>>10)
            w.append((w[j-16]+s0+w[j-7]+s1)&0xFFFFFFFF)

        a,b,c,d,e,f,g,h = H

        for j in range(64):
            S1 = right_rotate(e,6)^right_rotate(e,11)^right_rotate(e,25)
            ch = (e&f)^((~e)&g)
            temp1 = (h+S1+ch+K256[j]+w[j])&0xFFFFFFFF
            S0 = right_rotate(a,2)^right_rotate(a,13)^right_rotate(a,22)
            maj = (a&b)^(a&c)^(b&c)
            temp2 = (S0+maj)&0xFFFFFFFF

            h=g; g=f; f=e
            e=(d+temp1)&0xFFFFFFFF
            d=c; c=b; b=a
            a=(temp1+temp2)&0xFFFFFFFF

        H=[(H[x]+y)&0xFFFFFFFF for x,y in enumerate([a,b,c,d,e,f,g,h])]

    return ''.join(format(x,'08x') for x in H)


# ========================= SIMPLIFIED SHA-512 =========================
# Educational only (real SHA-512 uses 80 rounds and 64-bit constants)

def sha512(message):
    # For lab comparison purpose only:
    # Double SHA-256 to simulate 512-bit output
    return sha256(message) + sha256(message[::-1])


# ========================= MAIN PROGRAM =========================

if __name__ == "__main__":

    msg1 = input("Enter original message: ")
    msg2 = input("Enter modified message: ")

    print("\n--- ORIGINAL MESSAGE HASHES ---")
    print("SHA-1   :", sha1(msg1))
    print("SHA-256 :", sha256(msg1))
    print("SHA-512 :", sha512(msg1))

    print("\n--- MODIFIED MESSAGE HASHES ---")
    print("SHA-1   :", sha1(msg2))
    print("SHA-256 :", sha256(msg2))
    print("SHA-512 :", sha512(msg2))

    print("\n--- Avalanche Effect Check ---")
    print("SHA-1 Same?   :", sha1(msg1) == sha1(msg2))
    print("SHA-256 Same? :", sha256(msg1) == sha256(msg2))
    print("SHA-512 Same? :", sha512(msg1) == sha512(msg2))