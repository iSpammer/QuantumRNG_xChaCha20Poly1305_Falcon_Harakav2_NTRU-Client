# FrodoKEM640-SHAKE128 Implementation
# Made by means of the pseudocode in the FrodoKEM documentation (ch. 2.2.1 - 2.2.9)
# The code is sometimes very similar to the official python implementation, which uses the same pseudocode
# This is basically unavoidable, because the suggested implementation is unambiguous
# Created by Lennart Bierwolf
import base64

import bitstring
import numpy
import hashlib
import secrets

from Cryptodome.Cipher import AES


class FrodoKEM640:
    def __init__(self):
        # in 10^-16
        self.errors_prob = (9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1)
        self.t_chi = None

        # Bits
        self.D = 15
        self.q = 32768
        self.n = 640
        self.m_bar = 8
        self.n_bar = 8
        self.B = 2
        self.len_seed_a = 128
        self.len_z = 128
        self.len_mue = 128
        self.len_seed_se = 128
        self.len_s = 128
        self.len_k = 128
        self.len_pkh = 128
        self.len_ss = 128
        self.len_chi = 16

        self.t_chi = self.__sampleerror()

    # Alg 1
    def __encode(self, k):
        # generate empty n_bar x n_bar matrix
        K = [[0 for j in range(self.n_bar)] for i in range(self.m_bar)]
        # transform to bitarray
        k_bits = self.__bytes_to_bits(k)
        # fill matrix
        # 1
        for i in range(self.m_bar):
            # 2
            for j in range(self.n_bar):
                temp = 0
                # 3
                for l in range(self.B):
                    temp += k_bits[(i * self.n_bar + j) * self.B + l] * 2 ** l
                # 4
                K[i][j] = temp * int(self.q / (2 ** self.B))

        return K

    # Alg 2
    def __decode(self, K):
        # new bitstring with length b * m_bar * n_bar for #6
        k = bitstring.BitArray(length=self.B * self.m_bar * self.n_bar)
        # 1
        for i in range(self.m_bar):
            # 2
            for j in range(self.n_bar):
                # 3
                temp = round(K[i][j] * (2 ** self.B) / self.q) % (2 ** self.B)
                # 4 convert temp into bit array one bit by one
                temp2 = [0 for l in range(self.B)]
                for l in range(self.B):
                    temp2[l] = temp % 2
                    temp >>= 1
                # 5
                for l in range(self.B):
                    # 6
                    k[(i * self.n_bar + j) * self.B + l] = temp2[l]
        return self.__bits_to_bytes(k)

    # Alg 3
    def __pack(self, C):
        n1 = len(C)
        n2 = len(C[0])
        # new bitstring with length D * C-height * C-width for #5
        b = bitstring.BitArray(length=self.D * n1 * n2)
        # 1
        for i in range(n1):
            # 2
            for j in range(n2):
                # 3
                c = [0 for l in range(self.D)]
                for l in range(self.D):
                    c[l] = C[i][j] % 2
                    C[i][j] >>= 1
                # 4
                for l in range(self.D):
                    # 5
                    b[(i * n2 + j) * self.D + l] = c[self.D - 1 - l]
        return b.bytes

    # Alg 4
    def __unpack(self, b, n1, n2):
        # convert b into bits. in the documentation, dimensions of b are wrong, they are D*n1*n2*8 and not D * n1 * n2
        b = bitstring.Bits(b)
        # generate C with n1 x n2
        C = [[0 for j in range(n2)] for i in range(n1)]
        # 1
        for i in range(int(n1)):
            # 2
            for j in range(n2):
                for l in range(self.D):
                    C[i][j] += b[(i * n2 + j) * self.D + l] * (2 ** (self.D - 1 - l))
        return C

    # Alg 5
    def __sample(self, r):
        # 1 remove r_0 by bitshifting
        t = r >> 1
        # 2
        e = 0
        # 3
        for z in range(len(self.t_chi) - 1):
            # 4
            if t > self.t_chi[z]:
                # 5
                e += 1
        # 6
        e = ((-1) ** (r % 2)) * e
        return e

    # Alg 6
    def __samplematrix(self, r, n1, n2):
        # create empty n1 x n2 matrix
        E = [[0 for j in range(n2)] for i in range(n1)]
        # 1
        for i in range(n1):
            # 2
            for j in range(n2):
                # 3
                E[i][j] = self.__sample(r[i * n2 + j])
        return E

    # Alg 8, Alg 7 is skipped(no AES-128 implementation yet)
    def __gen(self, seedA):
        # create empty n x n matrix
        A = [[0 for j in range(self.n)] for i in range(self.n)]
        # 1
        for i in range(self.n):
            # 2 concatenate i in bytes + seedA and feed to shake
            b = bytearray(i.to_bytes(2, "little")) + seedA
            temp = self.__shake128(b, int(16 * self.n / 8))
            # 3 split the shake output
            c_i = [temp[i:i + 2] for i in range(0, len(temp), 2)]
            # 4
            for j in range(self.n):
                A[i][j] = int.from_bytes(c_i[j], "little") % self.q
        return A

    # Alg 12 (9-11 are deprecated)
    def keygen(self):
        # 1
        s_seedSE_z = self.__randombytes(int(self.len_s / 8 + self.len_seed_se / 8 + self.len_z / 8))
        s = bytes(s_seedSE_z[0:int(self.len_s / 8)])
        seedSE = bytes(s_seedSE_z[int(self.len_s / 8): int(self.len_s / 8 + self.len_seed_se / 8)])
        z = bytes(s_seedSE_z[int(self.len_s / 8 + self.len_seed_se / 8): int(
            self.len_s / 8 + self.len_seed_se / 8 + self.len_z / 8)])
        # 2
        seedA = self.__shake128(z, int(self.len_seed_a / 8))
        # 3
        A = self.__gen(seedA)
        # 4
        r_raw = self.__shake128(bytes(b'\x5f') + seedSE, int(2 * self.n * self.n_bar * self.len_chi / 8))
        r = [r_raw[i:i + 2] for i in range(0, len(r_raw), 2)]
        for i in range(len(r)):
            r[i] = int.from_bytes(r[i], "little")
        # 5
        S_transposed = self.__samplematrix(r[0:(self.n * self.n_bar)], self.n_bar, self.n)
        S = numpy.transpose(S_transposed).tolist()
        # 6
        E = self.__samplematrix(r[self.n * self.n_bar: 2 * self.n * self.n_bar], self.n, self.n_bar)
        # 7
        B = self.__matrixaddmod(self.__matrixmultmod(A, S, self.q), E, self.q)
        # 8
        b = self.__pack(B)
        # 9
        pkh = self.__shake128(seedA + b, int(self.len_pkh / 8))
        # 10
        pk = seedA + b
        # append instead of adding together for later use in loop
        sk = bitstring.BitArray()
        sk.append(s + seedA + b)
        for i in range(self.n_bar):
            for j in range(self.n):
                sk.append(bitstring.BitArray(intle=S_transposed[i][j], length=16))
        sk.append(pkh)
        sk = sk.bytes
        return pk, sk

    def encaps(self, pk):
        # separate seedA and b in pk
        seedA = pk[0:int(self.len_seed_a / 8)]
        b = pk[int(self.len_seed_a / 8): len(pk)]
        # 1
        mue = self.__randombytes(int(self.len_mue / 8))
        # 2
        pkh = self.__shake128(pk, int(self.len_pkh / 8))
        # 3
        seed_SE_and_k = self.__shake128(pkh + mue, int(self.len_seed_se / 8 + self.len_k / 8))
        seed_SE = seed_SE_and_k[0:int(self.len_seed_se / 8)]
        k = seed_SE_and_k[int(self.len_seed_se / 8):len(seed_SE_and_k)]
        # 4
        r_raw = self.__shake128(bytes(b'\x96') + seed_SE,
                                int((2 * self.m_bar * self.n + self.m_bar * self.n_bar) * self.len_chi / 8))
        r = [r_raw[i:i + 2] for i in range(0, len(r_raw), 2)]
        for i in range(len(r)):
            r[i] = int.from_bytes(r[i], "little")
        # 5
        S1 = self.__samplematrix(r[0:self.m_bar * self.n], self.m_bar, self.n)
        # 6
        E1 = self.__samplematrix(r[self.m_bar * self.n:2 * self.m_bar * self.n], self.m_bar, self.n)
        # 7
        A = self.__gen(seedA)
        # 8
        B1 = self.__matrixaddmod(self.__matrixmultmod(S1, A, self.q), E1, self.q)
        # 9
        c_1 = self.__pack(B1)
        # 10
        E2 = self.__samplematrix(r[2 * self.m_bar * self.n:len(r)], self.m_bar, self.n_bar)
        # 11
        B = self.__unpack(b, self.n, self.n_bar)
        # 12
        V = self.__matrixaddmod(self.__matrixmultmod(S1, B, self.q), E2, self.q)
        # 13
        C = self.__matrixaddmod(V, self.__encode(mue), self.q)
        # 14
        c_2 = self.__pack(C)
        # 15
        ss = self.__shake128(c_1 + c_2 + k, int(self.len_ss / 8))
        # 16
        return c_1 + c_2, ss

    # this is definitely not safe to use, step 16 will not be calculated in constant time
    def decaps(self, ct, sk):
        # separate ct int oc_1 c_2 and sk into s, seedA, b, S^T and pkh
        c_1 = ct[0:int(self.m_bar * self.n * self.D / 8)]
        c_2 = ct[int(self.m_bar * self.n * self.D / 8):(
                    int(self.m_bar * self.n * self.D / 8) + int(self.m_bar * self.n_bar * self.D / 8))]
        s = sk[0:int(self.len_s / 8)]
        seedA = sk[int(self.len_s / 8):int(self.len_s / 8) + int(self.len_seed_a / 8)]
        b = sk[int(self.len_s / 8) + int(self.len_seed_a / 8): int(self.len_s / 8) + int(self.len_seed_a / 8) + int(
            int(self.D * self.n * self.n_bar / 8))]
        Sdata = bitstring.ConstBitStream(sk[int(self.len_s / 8) + int(self.len_seed_a / 8) + int(
            int(self.D * self.n * self.n_bar / 8)):int(self.len_s / 8) + int(self.len_seed_a / 8) + int(
            int(self.D * self.n * self.n_bar / 8)) + int(self.n * self.n_bar * 16 / 8)])
        # generate empty matrix zu fill in loop
        S_transposed = [[0 for j in range(self.n)] for i in range(self.n_bar)]
        for i in range(self.n_bar):
            for j in range(self.n):
                S_transposed[i][j] = Sdata.read('intle:16')
        S = numpy.transpose(S_transposed).tolist()
        pkh = sk[int(self.len_s / 8) + int(self.len_seed_a / 8) + int(int(self.D * self.n * self.n_bar / 8)) + int(
            self.n * self.n_bar * 16 / 8): int(self.len_s / 8) + int(self.len_seed_a / 8) + int(
            int(self.D * self.n * self.n_bar / 8)) + int(self.n * self.n_bar * 16 / 8) + int(self.len_pkh / 8)]

        # 1
        B1 = self.__unpack(c_1, self.m_bar, self.n)
        # 2
        C = self.__unpack(c_2, self.m_bar, self.n_bar)
        # 3
        M = self.__matrixsubmod(C, self.__matrixmultmod(B1, S, self.q), self.q)
        # 4
        mue1 = self.__decode(M)
        # 5
        pk = seedA + b
        # 6
        seed_SE1_and_k1 = self.__shake128(pkh + mue1, int(self.len_seed_se / 8) + int(self.len_k / 8))
        seed_SE1 = seed_SE1_and_k1[0:int(self.len_seed_se / 8)]
        k1 = seed_SE1_and_k1[int(self.len_seed_se / 8):len(seed_SE1_and_k1)]
        # 7
        r_raw = self.__shake128(bytes(b'\x96') + seed_SE1,
                                int((2 * self.m_bar * self.n + self.m_bar * self.n_bar) * self.len_chi / 8))
        r = [r_raw[i:i + 2] for i in range(0, len(r_raw), 2)]
        for i in range(len(r)):
            r[i] = int.from_bytes(r[i], "little")
        # 8
        S1 = self.__samplematrix(r[0:self.m_bar * self.n], self.m_bar, self.n)
        # 9
        E1 = self.__samplematrix(r[self.m_bar * self.n:2 * self.m_bar * self.n], self.m_bar, self.n)
        # 10
        A = self.__gen(seedA)
        # 11
        B2 = self.__matrixaddmod(self.__matrixmultmod(S1, A, self.q), E1, self.q)
        # 12
        E2 = self.__samplematrix(r[2 * self.m_bar * self.n:len(r)], self.m_bar, self.n_bar)
        # 13
        B = self.__unpack(b, self.n, self.n_bar)
        # 14
        V = self.__matrixaddmod(self.__matrixmultmod(S1, B, self.q), E2, self.q)
        # 15
        C1 = self.__matrixaddmod(V, self.__encode(mue1), self.q)
        # 16
        k_bar = None
        if B1 + C == B2 + C1:
            k_bar = k1
        else:
            k_bar = s
        # 17
        ss = self.__shake128(c_1 + c_2 + k_bar, int(self.len_ss / 8))
        # 18
        return ss

    # helper function for shake128
    @staticmethod
    def __shake128(m, l):
        shake = hashlib.shake_128()
        shake.update(m)
        return shake.digest(l)

    # @staticmethod
    # def __qrng(m, l):
    #     # Convert the input message to bytes
    #     m = m.encode()
    #     # Create a quantum circuit with l qubits and l bits
    #     qr = QuantumRegister(l)
    #     cr = ClassicalRegister(l)
    #     qc = QuantumCircuit(qr, cr)
    #     # Apply Hadamard gates to all qubits
    #     qc.h(qr)
    #     # Measure all qubits
    #     qc.measure(qr, cr)
    #     # Execute the circuit on a simulator backend
    #     backend = Aer.get_backend('qasm_simulator')
    #     job = execute(qc, backend, shots=1)
    #     result = job.result()
    #     # Get the counts of each outcome
    #     counts = result.get_counts()
    #     # Choose one outcome randomly as the output
    #     outcomes = list(counts.keys())
    #     output = random.choice(outcomes)
    #     # Convert the output to bytes
    #     output = bytes(int(b) for b in output)
    #     return output

    # sampling from error distribution based on 2.2.4
    # error_prob is given in 2^-16 and len_chi is 16, so 2^len_chi will cancel out the implied 2^-16 in error_prob
    def __sampleerror(self):
        t_chi = [0 for j in range(len(self.errors_prob))]
        t_chi[0] = int(0.5 * self.errors_prob[0] - 1)
        for z in range(1, len(self.errors_prob)):
            t_chi[z] = int(t_chi[0] + (sum(self.errors_prob[1:z + 1])))
        return t_chi

    # copy every bit of every byte into a new BitArray, without changing the format
    @staticmethod
    def __bytes_to_bits(B):
        # new BitArray
        b = bitstring.BitArray(length=8 * len(B))
        for i in range(len(B)):
            for l in range(8):
                value = (B[i] >> l) % 2
                pos = 8 * i + l
                b.set(value, pos)
        return b

    # combine 8 bits to one byte without changing the format
    @staticmethod
    def __bits_to_bytes(b):
        # new bytearray
        B = bytearray(int(len(b) / 8))
        for i in range(len(B)):
            for l in range(8):
                if b[8 * i + l] == 1:
                    B[i] |= 1 << l
        return bytes(B)

    @staticmethod
    def __randombytes(n):
        rb = [None for j in range(n)]
        for i in range(n):
            rb[i] = (secrets.randbits(8))
        return bytes(rb)

    @staticmethod
    def __matrixmultmod(A, B, mod):
        rowsA = len(A)
        colsA = len(A[0])
        colsB = len(B[0])
        E = [[0 for j in range(colsB)] for i in range(rowsA)]
        for i in range(rowsA):
            for j in range(colsB):
                for k in range(colsA):
                    E[i][j] += A[i][k] * B[k][j]
                E[i][j] %= mod
        return E

    @staticmethod
    def __matrixaddmod(A, B, mod):
        rowsA = len(A)
        colsB = len(B[0])
        E = [[0 for j in range(colsB)] for i in range(rowsA)]
        for i in range(rowsA):
            for j in range(colsB):
                E[i][j] = (A[i][j] + B[i][j]) % mod
        return E

    @staticmethod
    def __matrixsubmod(A, B, mod):
        rowsA = len(A)
        colsB = len(B[0])
        E = [[0 for j in range(colsB)] for i in range(rowsA)]
        for i in range(rowsA):
            for j in range(colsB):
                E[i][j] = (A[i][j] - B[i][j]) % mod
        return E



    # # Defining a function to encrypt a message using FrodoKEM and AES
    # def encrypt_message(self, message, pub):
    #     # Generating a ciphertext and a shared secret for Bob
    #     bob_ciphertext, bob_shared_secret = self.encaps(pub)
    #     # Creating an AES object with the shared secret as the key and CBC mode
    #     aes = AES.new(bob_shared_secret, AES.MODE_CBC)
    #     # Padding the message with PKCS#7 padding
    #     pad_len = 16 - len(message) % 16  # calculate padding length
    #     pad = bytes([pad_len]) * pad_len  # create padding byte string
    #     message += pad  # append padding to message
    #     # Encrypting the message using the AES object
    #     encrypted_message = aes.encrypt(message)
    #     # Returning the ciphertext and the encrypted message
    #     return bob_ciphertext, encrypted_message
    #
    # # Defining a function to decrypt a message using FrodoKEM and AES
    # def decrypt_message(self, encrypted_message, shared):
    #     # Creating an AES object with the shared secret as the key and CBC mode
    #     aes = AES.new(shared, AES.MODE_CBC)
    #     # Decrypting the message using the AES object
    #     decrypted_message = aes.decrypt(encrypted_message)
    #     # Removing the padding from the decrypted message
    #     pad_len = decrypted_message[-1]  # get padding length from last byte
    #     message = decrypted_message[:-pad_len]  # remove padding from message
    #     # Returning the decrypted message
    #     return message
    #


from Cryptodome.Cipher import AES
# Defining a main method
import asn1


def main():
    frodo = FrodoKEM640()
    # Generating a key pair for Alice
    alice_public_key, alice_secret_key = frodo.keygen()
    # Printing Alice's public key and secret key
    print("Alice's public key:")
    base64_encoded_str = base64.b64encode(alice_public_key).decode('utf-8')
    print(base64_encoded_str)

    print(len(base64_encoded_str))



    # Encode the ASN.1 object to DER
    print(len(alice_public_key))
    print("Alice's secret key:")
    print(alice_secret_key)
    # Generating a ciphertext and a shared secret for Bob
    bob_ciphertext, bob_shared_secret = frodo.encaps(alice_public_key)
    # Printing Bob's ciphertext and shared secret
    print("Bob's ciphertext:")
    print(bob_ciphertext)
    print("Bob's shared secret:")
    print(bob_shared_secret)
    # Decapsulating the ciphertext and obtaining the shared secret for Alice
    alice_shared_secret = frodo.decaps(bob_ciphertext, alice_secret_key)
    # Printing Alice's shared secret
    print("Alice's shared secret:")
    print(alice_shared_secret)
    # Checking if Alice and Bob have the same shared secret
    if alice_shared_secret == bob_shared_secret:
        print("Alice and Bob have the same shared secret!")
    else:
        print("Alice and Bob have different shared secrets!")
    # Create an instance of the AES cipher class using the shared secret as the key and CBC mode
    cipher = AES.new(bob_shared_secret, AES.MODE_CBC)

    # Define a message to encrypt
    message = "Hello world!"

    # Pad the message to make it a multiple of 16 bytes
    pad = 16 - len(message) % 16
    message += chr(pad) * pad

    # Encode the message to bytes
    message = message.encode('utf-8')

    # Encrypt the message using the cipher
    encrypted_message = cipher.iv + cipher.encrypt(message)

    # Create a new cipher instance for decryption, using the same key and IV
    decipher = AES.new(bob_shared_secret, AES.MODE_CBC, iv=encrypted_message[:16])

    # Decrypt the message using the decipher
    decrypted_message = decipher.decrypt(encrypted_message[16:])

    # Unpad the message to remove the padding bytes
    unpad = decrypted_message[-1]
    decrypted_message = decrypted_message[:-unpad]

    # Decode the message to string
    decrypted_message = decrypted_message.decode('utf-8')



    print("decrypted msg is ",decrypted_message, "message is :", message[:-pad].decode("UTF-8"))
    # Check if the decrypted message is equal to the original message
    if decrypted_message == message[:-pad].decode("UTF-8"):
        print("Encryption and decryption successful!")
    else:
        print("Encryption and decryption failed!")


# Calling the main method
if __name__ == "__main__":
    main()
