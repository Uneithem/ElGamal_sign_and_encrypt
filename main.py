# this program uses syspy module for primitive roots search. For documentation please check https://docs.sympy.org/latest/modules/ntheory.html
from math import gcd
import random
import hashlib
from sympy.ntheory.residue_ntheory import primitive_root


# All we need to find all primitive roots is just one, and the rest are generated from found one (I'll call it
# generator root) with g^s (mod p), where g is generator and s is coprime to phi(p) = p - 1 - Euler's totient function
def rootsGenerate(p):
    # primitive_root(p) finds smallest primitive root modulo p, it's declared as generator
    primitive_generator = primitive_root(p)
    roots = [primitive_generator]
    # It's extremely time-consuming to find all primitive roots, that's why only small portion of them are calculated
    for s_i in range(2, (p - 1) // 2):
        if gcd(s_i, (p - 1) // 2) == 1:
            roots.append(pow(primitive_generator, s_i, p))
        else:
            pass
        if len(roots) > 1000:
            break
    return roots


# primality check function based on Miller-Rabin test
def PrimalityCheck(m):
    primary_num = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    m = int(m, 2)
    for i in range(0, len(primary_num)):
        if m % primary_num[i] == 0:
            return False
    r = m - 1
    while r % 2 == 0:
        r //= 2
    # higher amount of iterations is desired, but not necessary
    # you may increase amount of iterations if you desire higher accuracy
    for i in range(0, 40):
        a = 2 + random.randint(1, m - 4)
        x = pow(a, r, m)
        if x == 1 or x == m - 1:
            return True
        while r != m - 1:
            x = (x * x) % m
            r *= 2
            if x == 1:
                return False
            if x == m - 1:
                return True
        return False


def GeneratePrime(keylength=1024):
    h = ''
    num_iter = keylength // 4
    # Generating hex numbers with random and then turning them into binary has shown to be faster than
    # generating 0 and 1 bits in approximately half of the tests
    for i in range(0, num_iter):
        h += bin(random.randint(0, 15))[2:].zfill(4)
    # If generated number passes primality check already then it's passed down the program
    if PrimalityCheck(h):
        return h
    # Otherwise, new one generated until the one which passes the test is generated
    else:
        # Usually, amount of iterations exceeds 992 and python throws Recursion Error, following code
        # is made to guarantee that a number is generated at every instance
        try:
            h = GeneratePrime(keylength)
            return h
        except RecursionError:
            h = GeneratePrime(keylength)
            return h

# key generation in ElGamal algorythm
def keyGen(p, g):
    a = random.randint(2, p - 1)
    b = pow(g, a, p)
    return a, b


def sign(message, private_key, p, g):
    message = message.encode()
    hashed = int(hashlib.sha256(message).hexdigest(), 16)
    k = random.randint(2, p - 1)
    # since not all numbers have multiplicative inverse in every base, several numbers might be generated until found one which has inverse modulo p
    try:
        test = pow(k, -1, p - 1)
    except ValueError:
        while True:
            try:
                k = random.randint(2, p - 1)
                test = pow(k, -1, p - 1)
                break
            except ValueError as err:
                pass
    r = pow(g, k, p)
    s = ((hashed - private_key * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def verify(message, signature, public_key):
    message = message.encode()
    if signature[0] < 1 or signature[0] > public_key[1] or signature[1] < 1 or signature[1] > public_key[1] - 1:
        return False
    hashed = int(hashlib.sha256(message).hexdigest(), 16)
    if pow(public_key[0], signature[0], public_key[1]) * pow(signature[0], signature[1], public_key[1]) % public_key[1] == pow(public_key[2], hashed, public_key[1]):
        return True
    else:
        return False


def encrypt(m, public_key):
    m_digest = ''
    for char in m:
        m_digest += bin(ord(char))[2:].zfill(8)
    m_digest = int(m_digest, 2)
    k = random.randint(1, public_key[1] - 2)
    x = pow(public_key[2], k, public_key[1])
    y = (pow(public_key[0], k, public_key[1]) * m_digest) % public_key[1]
    return x, y


def decrypt(ciphertext, p, private):
    s = pow(ciphertext[0], private, p)
    m = ciphertext[1] * pow(s, -1, p) % p
    return m

# Testing function for signature, to make it faster, p and primitive roots list are generated outside the function to be used in signature and encryption tests
def signatureTest(p, prim_roots):
    g = random.choice(prim_roots)
    private, b = keyGen(p, g)
    public = (b, p, g)
    signat = sign("message", private, public[1], public[2])
    print("First test where anything hasn't been modified")
    if verify("message", signat, public):
        print("Signature is authentic")
    else:
        print("Signature or public key are compromised")
    g0 = random.choice(prim_roots)
    while g0 == g:
        g0 = random.choice(prim_roots)
    public1 = (b, p, g0)
    print("Second test where public key has been modified")
    if verify("message", signat, public1):
        print("Signature is authentic")
    else:
        print("Signature or public key are compromised")
    print("Third test where signature has been modified")
    signat1 = (signat[0] + p, signat[1])
    if verify("message", signat1, public):
        print("Signature is authentic")
    else:
        print("Signature or public key are compromised")


def encryptionTest(p, prim_roots):
    g = random.choice(prim_roots)
    private, b = keyGen(p, g)
    public = (b, p, g)
    m = "Hello world"
    m1 = ''
    for char in m:
        m1 += bin(ord(char))[2:].zfill(8)
    cipher = encrypt(m, public)
    print("First test, where encryption and decryption are made as supposed to be. Status of original message being equal to decrypted one: ", int(m1, 2) == decrypt(cipher, public[1], private))
    cipher1 = (cipher[0] + cipher[1], cipher[1])
    print("Second test, where ciphertext is modified. Status of original message being equal to decrypted one: ", int(m1, 2) == decrypt(cipher1, public[1], private))
    print("Third test with the wrong private key. Status of original message being equal to decrypted one: ", int(m1, 2) == decrypt(cipher, public[1], private*8))


# Note: desired key length is between 2048 and 4096 bits. However, it is extremely time-consuming to find primitive 
# roots for such moduli, so, for testing it's better to use smaller key lengths or to use already generated p
# and at least one primitive root of p if it's known
# For actual encryption and signing key must be generated and then stored for some time, since generating new key 
# every time is just not efficient
p = int(GeneratePrime(256), 2)
prim_roots = rootsGenerate(p)
signatureTest(p, prim_roots)
encryptionTest(p, prim_roots)
