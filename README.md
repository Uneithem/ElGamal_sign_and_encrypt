# ElGamal_sign_and_encrypt
Python implementation of message signing and encryption using ElGamal algorythm

This program uses sympy library for operations with large prime numbers. For documentation please review: https://docs.sympy.org/latest/modules/ntheory.html

#How to use
Firstly: generate p - prime and list of g - primitive roots modulo p using:

p = int(GeneratePrime(*desired keylength*), 2)
prim_roots = rootsGenerate(p)

Secondly: generate private and public keys using following code:

g = random.choice(prim_roots)
private, b = keyGen(p, g)
public = (b, p, g)

Now, if you need to sign a message run:

message = *Your message*
signature = sign(message, private, public[1], public[2])
*Output type is a tuple consisting of two integers*

To verify signature:

verify(message, signature, public)
*Output type of verify is boolean value: True if signature is authentic and False is something is wrong*

To encrypt a message:

message = *Your message*
cipher = encrypt(message, public)

To decrypt:

print(decrypt(cipher, public[1], private))


#Testing functions output:
*signing*:

*First test where anything hasn't been modified
Signature is authentic
Second test where public key has been modified
Signature or public key are compromised
Third test where signature has been modified
Signature or public key are compromised*

*encryption*:

*First test, where encryption and decryption are made as supposed to be. Status of original message being equal to decrypted one:  True
Second test, where ciphertext is modified. Status of original message being equal to decrypted one:  False
Third test with the wrong private key. Status of original message being equal to decrypted one:  False*
