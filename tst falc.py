# Import the ntru and falcon packages
from NTRU import ntru
from falcon import falcon
import numpy as np

#Bob
print("Bob Will Generate his Public Key using Parameters")
print("N=7,p=29 and q=491531")
Bob = ntru.Ntru(7, 29, 491531)
f = [1, 1, -1, 0, -1, 1]
g = [-1, 0, 1, 1, 0, 0, -1]
d = 2
print("f(x)= ", f)
print("g(x)= ", g)
print("d   = ", d)
Bob.genPublicKey(f, g, 2)
pub_key = Bob.getPublicKey()
print("Public Key Generated by Bob: ", pub_key)

# Bob also generates a signature key pair using falcon
print("Bob Will Generate his Signature Key Pair using Security Level 1")
Bob_s = falcon.SecretKey(32)
pub_key_s = falcon.PublicKey(Bob_s)
print("Signature Public Key Generated by Bob: ", pub_key_s)

# Bob saves both public keys to a file and sends it to Alice
np.savez("Bob_keys.npz", pub_key=pub_key, pub_key_s=pub_key_s)
print("Public keys saved to Bob_keys.npz file")
mssg = "ntru_pub="+str(pub_key)+'digi'+str(pub_key_s)
mssg = str.encode(mssg)
sig = Bob_s.sign((mssg))
print("signing,",sig)
print("\n-------------------------------------------------\n")
#Alice
Alice = ntru.Ntru(7, 29, 491531)

# Alice receives the public keys from Bob and loads them from the file
Bob_keys = np.load("Bob_keys.npz", allow_pickle=True)
pub_key = Bob_keys["pub_key"]
pub_key_s = Bob_keys["pub_key_s"]
print("Public keys loaded from Bob_keys.npz file")

# Alice sets the encryption public key as her public key
Alice.setPublicKey(pub_key)

Alice_pub = falcon.PublicKey(n=32, h=str.encode(str(pub_key)))
print("aliiic ", Alice_pub)
# Alice verifies the signature public key by checking the security level and the inverse
if Alice_pub.verify(mssg, sig):
    print("Signature public key verified")
else:
    print("Signature public key invalid")

msg = []

# number of elemetns as input
n = int(input("Enter number of elements : "))

# iterating till the range
for i in range(0, n):
    ele = int(input())

    msg.append(ele)  # adding the element

print(msg)
#msg = [1, 1, 0, 0, 1, 0, 1]
print("Alice's Original Message   : ", msg)
ranPol = [-1, -1, 1, 1]
print("Alice's Random Polynomial  : ", ranPol)
encrypt_msg = Alice.encrypt(msg,ranPol)
print("Encrypted Message          : ", encrypt_msg)

# Alice sends the encrypted message to Bob
print("\n-------------------------------------------------\n")
#BOB
print("Bob decrypts message sent to him")
print("Decrypted Message          : ", Bob.decrypt(encrypt_msg))

# Bob signs the message using his signature private key
sign_msg = Bob_s.sign(msg)
print("Signed Message             : ", sign_msg)

# Bob sends the signature and the message to Alice
print("\n-------------------------------------------------\n")
#Alice
print("Alice verifies the signature sent by Bob")
# Alice verifies the signature using Bob's signature public key
if Alice_s.verify(sign_msg, msg, pub_key_s):
    print("Signature verified")
else:
    print("Signature invalid")
