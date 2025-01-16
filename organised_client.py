import ast
import base64
import hashlib
import json
import os
import random
import struct
from base64 import b64encode, b64decode

import numpy as np
from Crypto.Cipher import ChaCha20_Poly1305
from scapy.all import *
from scapy.layers.inet import IP

from CA_CONNECTION import request_handler
from NTRU import ntru
from falcon import falcon
from harakav2 import pad_message, haraka512256

# Load client certificate data
data_client = np.load('client_cert.npy', allow_pickle='TRUE').item()
pub_key = data_client['pub_key_s_h']
priv_key_sf = data_client['sk_f']
priv_key_sg = data_client['sk_g']

print("pub_key_s_h ", (pub_key))
print("priv_key_sf ", (priv_key_sf))
print("priv_key_sg ", (priv_key_sg))

# Initialize NTRU
Challenge = ntru.Ntru(7, 29, 491531)
Challenge.genPublicKey(priv_key_sf, priv_key_sg, 2)

# Server configuration
SERVER_IP = "192.168.68.139"
SERVER_PORT = 4449
CLIENT_IP = "192.168.68.143"

# Global variables
shared_secret = None
qrng_nonce = None


class EncryptedTCP(Packet):
    name = "EncryptedTCP"
    fields_desc = [
        StrFixedLenField("sport", b"\x00\x00\x00\x00\x00", 5),
        StrFixedLenField("dport", b"\x00\x00\x00\x00\x00", 5),
        IntField("seq", 0),
        IntField("ack", 0),
        BitField("dataofs", None, 4),
        BitField("reserved", 0, 3),
        FlagsField("flags", 0x2, 9, "FSRPAUECN"),
        ShortField("window", 8192),
        XShortField("chksum", None),
        ShortField("urgptr", 0),
        PacketListField("options", []),
    ]


# Bind the custom layer to the IP layer
bind_layers(IP, EncryptedTCP, proto=99)


def sign_fn(payload, qrng, header):
    global shared_secret
    cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=qrng)
    cipher.update(header)
    secret_key_sign = falcon.SecretKey(32)
    public_key_sign = falcon.PublicKey(secret_key_sign)
    sign_str = secret_key_sign.sign(payload)
    pk_arr = public_key_sign.h
    pk_arr = struct.pack('>' + 'h' * len(pk_arr), *pk_arr)
    payload = payload + b"<|>" + sign_str + b"<|>" + pk_arr

    ciphertext, tag = cipher.encrypt_and_digest(payload)
    jk = ['nonce', 'header', 'ciphertext', 'tag']
    jv = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
    result = json.dumps(dict(zip(jk, jv)))
    return result


def check_signature(payload, challenge=False):
    global shared_secret, qrng_nonce
    if challenge:
        b64 = json.loads(payload)
        plaintext = Challenge.decrypt(b64['ciphertext'])
        return plaintext == [1, 0, 1, 0, 1, 1, 2]
    else:
        try:
            b64 = json.loads(payload)
            jk = ['nonce', 'header', 'ciphertext', 'tag']
            jv = {k: b64decode(b64[k]) for k in jk}
            cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

            blockhash, sign_str, pk_arr, qrng_nonce_client = plaintext.split(b'<|>')
            sign_str = bytes(sign_str)

            pk_fn = falcon.PublicKey(n=32, h=list(struct.unpack('>' + 'h' * (len(pk_arr) // 2), pk_arr)))
            check = pk_fn.verify(blockhash, bytes(sign_str))

            print("Verification status:", check)
            print("Decrypted hash:", blockhash)

            qrng_nonce = qrng_nonce_client
            return blockhash, check, qrng_nonce_client
        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None, False, None


def perform_key_exchange():
    global shared_secret

    ip_pkt = IP(dst=SERVER_IP, proto=99)
    syn = ip_pkt / EncryptedTCP(flags="S", reserved=7)
    syn_ack = sr(syn)
    ack = ip_pkt / EncryptedTCP(flags="A")
    msg1 = sr1(ack)

    if len(msg1[Raw].load) >= 0:
        params, pub_key = msg1[Raw].load.split(b'|')
        N, p, q = map(int, params.decode().split(','))
        pub_key = ast.literal_eval(pub_key.decode("UTF-8"))

        print("Parameters Received from Server:", N, p, q)
        print("Public Key Received from Server:", pub_key)

        Alice = ntru.Ntru(N, p, q)
        Alice.setPublicKey(pub_key)

        message = [1, 1, 0, 0, 1, 0, 1]
        ranPol = [-1, -1, 1, 1]
        reply1 = Alice.encrypt(message, ranPol)

        pkt1 = ip_pkt / EncryptedTCP(flags="PA") / str(reply1)
        send(pkt1)

        message = pad_message(bytes(message))
        shared_secret = bytes(haraka512256(message))
        print("Shared Secret:", shared_secret.hex())

        return ip_pkt
    else:
        print("Error: Did not receive expected data from server")
        return None


def main():
    global qrng_nonce
    print("Client starting...")

    ip_pkt = perform_key_exchange()
    if not ip_pkt:
        return

    msg2 = sniff(filter=f"ip and host {CLIENT_IP}", count=1)[0]

    if len(msg2[Raw].load) > 10:
        blockhash, check, qrng_nonce = check_signature(msg2[Raw].load)
        if check:
            print("Server certificate verified")
            blockhash_list = re.findall(r'\d+', blockhash.decode('ascii', errors='ignore'))
            blockhash_list = [int(x) for x in blockhash_list]

            print("PKI HASH VERIFICATION STATUS ",
                  request_handler.get_request(SERVER_IP, qrng_nonce, ip_pkt, blockhash_list))

        else:
            print("Server certificate verification failed")
            return

        client_cert = json.dumps(pub_key)
        client_cert = bytes(client_cert, 'utf-8')
        signed_cert = sign_fn(client_cert, header=b"client_hash", qrng=qrng_nonce)
        pkt2 = ip_pkt / EncryptedTCP(flags="PA") / signed_cert
        send(pkt2)

        while True:
            user_msg = input("Enter a message to send to the server (or 'bye' to exit): ")
            if user_msg.lower() == 'bye':
                fin = IP(dst=SERVER_IP) / EncryptedTCP(flags="FA")
                send(fin)
                ack_fin = IP(dst=SERVER_IP) / EncryptedTCP(flags="A")
                send(ack_fin)
                break

            user_msg_enc = sign_fn(user_msg.encode(), header=b"data_exchange_" + str(random.randint(-99, 99)).encode(),
                                   qrng=qrng_nonce)
            pkt3 = IP(dst=SERVER_IP) / EncryptedTCP(flags="PA") / user_msg_enc
            send(pkt3)

            reply2 = sniff(filter=f"ip and src {SERVER_IP} and dst {CLIENT_IP}", count=1)[0]
            reply_dec, verif, qrng_nonce = check_signature(reply2[Raw].load)
            if verif:
                print("Reply from server:", reply_dec.decode("UTF-8"))
            else:
                print("Failed to verify server response")

    print("Client shutting down...")


if __name__ == "__main__":
    main()