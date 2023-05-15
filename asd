# Import scapy and random modules
import hashlib

import chacha20poly1305
from scapy.all import *
import random
import struct
from NTRU import ntru
import pyspx.haraka_256f
from chacha20poly1305 import ChaCha20Poly1305
from falcon import falcon
from scapy.layers.inet import IP, TCP
# import pyspx.haraka_256f
# Define the server IP and port
from harakav2 import *
import ast
server_ip = "192.168.68.139"
server_port = 4449

qrng_nonce = b'\xb8\x08\x9c\xd2\xea\xbe\xf7\x1e\xac\xf1\xd6$'


# Generate a random source port for the client
client_port = random.randint(1024, 65535)

# Create a TCP SYN packet with the server as the destination
syn = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="S")

# Send the SYN packet and receive the SYN-ACK packet from the server
syn_ack = sr1(syn)

# Create a TCP ACK packet to complete the handshake
ack = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="A", ack=syn_ack.seq + 1)
# Create a TCP socket
s = conf.L3socket()

# Send the ACK packet and receive the 700 bytes message from the server
msg1 = s.sr1(ack)
print("sent tcp, getting pub from server")
# Check if the message length is 700 bytes
if len(msg1[TCP].payload) >= 0:

    print("pub ", msg1[Raw].load.decode("UTF-8"))
    # Receive the parameters and the public key from the server (Bob)
    params, pub_key = msg1[Raw].load.split(b'|')
    N, p, q = map(int, params.decode().split(','))
    pub_key = pub_key.decode("UTF-8")

    pub_key = ast.literal_eval(pub_key)
    print("Parameters Received from Server: ", N, p, q)
    print("Public Key Received from Server: ", pub_key)

    # Create an instance of the Ntru class with the parameters received from Bob
    Alice = ntru.Ntru(N, p, q)

    # Alice sets her public key to be the same as Bob's
    Alice.setPublicKey(pub_key)

    # Alice generates a random message of length N
    message = [1, 1, 0, 0, 1, 0, 1]
    print("Alice's Original Message   : ", message)

    # Alice encrypts her message with Bob's public key
    ranPol = [-1, -1, 1, 1]
    print("Alice's Random Polynomial  : ", ranPol)
    reply1 = Alice.encrypt(message, ranPol)
    print("Encrypted Message          : ", reply1)

    # Create a TCP packet with the reply text as the payload
    pkt1 = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="PA", seq=ack.seq, ack=msg1.seq + len(msg1[TCP].payload))/str(reply1)
    # Send the packet and receive the 100 bytes message from the server
    print("sending client cipher")
    msg2 = s.sr1(pkt1)

    # Check if the message length is 100 bytes
    if len(msg2[TCP].payload) > 10:

        print("Encrypted String           : ", msg2[Raw].load)

        # Alice decrypts the encrypted string with the shared secret using XOR
        # shared_secret = hashlib.sha256(bytes(message)).hexdigest()
        message = pad_message(bytes(message))
        shared_secret = bytes(haraka512256(message))
        print("Shared Secret              : ", shared_secret)


        print("got server hash")
        print("enc hash : ",msg2[Raw].load)
        cipher = chacha20poly1305.ChaCha20Poly1305(shared_secret)

        dec_hash_sig = cipher.decrypt(qrng_nonce, msg2[Raw].load)
        print("decryped hash+sig ",dec_hash_sig)
        dec_hash, signature, pkh = dec_hash_sig.split(b'<|>')
        signature = bytes(signature)
        # dec_hash = dec_hash.decode("UTF-8")
        print("dec hash : ",dec_hash)

        pk = falcon.PublicKey(n=32, h=list(struct.unpack('>' + 'h' * (len(pkh) // 2), pkh)))
        # print("verification status = ", pyspx.haraka_256f.verify(dec_hash, signature, pub_key))
        verification = pk.verify(dec_hash, bytes(signature))
        # Create a message of around 100 bytes
        print("verification status "+str(verification))
        secret_key = falcon.SecretKey(32)
        public_key = falcon.PublicKey(secret_key)
        # Create a message of around 100 bytes
        msg3 = b"This is a message of around 100 bytes.\n"
        signature = secret_key.sign(msg3)
        pkh = public_key.h
        pkh = struct.pack('>' + 'h' * len(pkh), *pkh)
        msg3 = msg3 + b"<|>" + signature + b"<|>" + pkh

        msg3 = cipher.encrypt(qrng_nonce, msg3)

        # Create a TCP packet with the message as the payload
        pkt2 = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="PA", seq=pkt1.seq + len(pkt1[TCP].payload), ack=msg2.seq + len(msg2[TCP].payload))/msg3
        # Send the packet and receive the 100 bytes message from the server
        print("sending client hash")
        msg4 = s.sr1(pkt2)
        # Check if the message length is 100 bytes
        if len(msg4[TCP].payload) >=0 :
            # Enter a loop to exchange messages with the server until bye is sent or received
            while True:
                # Prompt the user to enter a message to send to the server
                user_msg = input("Enter a message to send to the server: ")
                user_msg_enc = cipher.encrypt(qrng_nonce, user_msg.encode())

                # Check if the user message contains bye
                if "bye" in user_msg.lower():
                    # Create a TCP FIN packet to close the connection
                    fin = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="FA", seq=pkt2.seq + len(pkt2[TCP].payload), ack=msg4.seq + len(msg4[TCP].payload))
                    # Send the FIN packet and receive the FIN-ACK packet from the server
                    fin_ack = s.sr1(fin)
                    # Create a TCP ACK packet to acknowledge the FIN-ACK packet
                    ack_fin = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="A", seq=fin_ack.ack, ack=fin_ack.seq + 1)
                    # Send the ACK packet and exit the loop
                    s.send(ack_fin)
                    break
                else:
                    # Create a TCP packet with the user message as the payload
                    pkt3 = IP(dst=server_ip)/TCP(dport=server_port, sport=client_port, flags="PA", seq=pkt2.seq + len(pkt2[TCP].payload), ack=msg4.seq + len(msg4[TCP].payload))/user_msg_enc
                    # Send the packet and receive the reply from the server
                    print("sending....")
                    s.send(pkt3)
                    reply2 = s.recv()
                    print("sent!, receving...", reply2.show())
                    reply_dec = cipher.decrypt(qrng_nonce, reply2[Raw].load)
                    # Print the reply from the server
                    print("Reply from server: " + reply_dec.decode("UTF-8"))
        else:
            # Print an error message if the message length is not 100 bytes
            print("Error: The message from server is not 100 bytes.")
    else:
        # Print an error message if the message length is not 700 bytes
        print("Error: The message from server is not 700 bytes.")


def sign(payload, qrng):
    signature = secret_key.sign(payload)
    pkh = public_key.h
    pkh = struct.pack('>' + 'h' * len(pkh), *pkh)
    payload = payload + b"<|>" + signature + b"<|>" + pkh

    payload = cipher.encrypt(qrng, payload)
    return payload


def check_signature(payload, qrng):
    