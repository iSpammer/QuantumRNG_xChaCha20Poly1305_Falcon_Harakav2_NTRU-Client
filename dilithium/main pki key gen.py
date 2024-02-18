import numpy as np

from dilithium import Dilithium2, Dilithium2_small
#
# # Example of signing
# pk, sk = Dilithium2.keygen()
#
#
#
# server_country = b"EG" # Country name
# server_state_code = b"Cairo" # State or province name
# server_state = b"New Cairo" # Locality name
# server_org = b"OSSTECH" # Organization name
# server_org_unit = b"RND" # Organizational unit name
# server_cname = b"server" # Common name
# server_email = b"server.osstech.com.eg" # Email address
# print(type(pk))
# msg = np.array([server_country, server_state_code, server_state, server_org, server_org_unit, server_cname, server_email, pk, sk])
#
# np.savez("server_cert.npz", x=msg)
# msg = msg.tobytes()
#
# print(msg)
# print("pk is ",type(pk))
# print("sk is ",sk)
# sig = Dilithium2.sign(sk, msg)
# print("enc is ",len(pk))


data_ca = np.load("../server_ca.npz")
print((data_ca['x']))

#
# import binascii
#
# # Define the original bytes object
# bytes_obj = data_ca['x'][7]
#
# # Convert the bytes to a base64 string using binascii.b2a_base64()
# base64_string = binascii.b2a_base64(bytes_obj).decode('ascii')
#
# # Print the base64 string
# print("b64", base64_string)
#
# # Encode the base64 string as ASCII bytes using str.encode()
# ascii_bytes = base64_string.encode('ascii')
#
# # Decode the ASCII bytes using binascii.a2b_base64()
# restored_bytes = binascii.a2b_base64(ascii_bytes)
#
# # Print the restored bytes
# print("res",restored_bytes)
#
# # Check if the restored bytes are equal to the original bytes
# print(restored_bytes == bytes_obj)
# Import the Dilithium2 class from the dilithium package
# Import some libraries for classical and quantum-resistant cryptography
import rsa
import ntru
import dilithium

# Generate classical and quantum-resistant key pairs for Alice and Bob
alice_rsa_public, alice_rsa_private = rsa.generate_keys()
alice_ntru_public, alice_ntru_private = ntru.generate_keys()
alice_dilithium_public, alice_dilithium_private = dilithium.generate_keys()

bob_rsa_public, bob_rsa_private = rsa.generate_keys()
bob_ntru_public, bob_ntru_private = ntru.generate_keys()
bob_dilithium_public, bob_dilithium_private = dilithium.generate_keys()

# Alice wants to send a message to Bob
message = "Hello Bob, this is Alice."

# Alice encrypts her message with Bob's public keys
encrypted_message = rsa.encrypt(message, bob_rsa_public) + ntru.encrypt(message, bob_ntru_public)

# Alice signs her message with her private keys
signature = rsa.sign(message, alice_rsa_private) + dilithium.sign(message, alice_dilithium_private)

# Alice sends the encrypted message and the signature to Bob
send(encrypted_message, signature)

# Bob receives the encrypted message and the signature from Alice
encrypted_message, signature = receive()

# Bob verifies the signature with Alice's public keys
if rsa.verify(message, signature, alice_rsa_public) and dilithium.verify(message, signature, alice_dilithium_public):
    # Bob decrypts the message with his private keys
    decrypted_message = rsa.decrypt(encrypted_message, bob_rsa_private) + ntru.decrypt(encrypted_message, bob_ntru_private)
    # Bob reads the message from Alice
    print(decrypted_message)
else:
    # Bob rejects the message as invalid
    print("Invalid signature")
