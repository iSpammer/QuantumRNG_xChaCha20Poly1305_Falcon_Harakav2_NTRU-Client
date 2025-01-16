import base64
import json
import random
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from scapy.all import *
from scapy.layers.inet import IP
import ast
from harakav2 import pad_message, haraka512256
from falcon import falcon
import numpy as np
from NTRU import ntru
from CA_CONNECTION import request_handler

# Load pre-calculated keys
data_client = np.load('client_cert.npy', allow_pickle='TRUE').item()
pub_key = data_client['pub_key_s_h']
priv_key_sf = data_client['sk_f']
priv_key_sg = data_client['sk_g']

print("pub_key_s_h ", pub_key)
print("priv_key_sf ", priv_key_sf)
print("priv_key_sg ", priv_key_sg)

# Initialize NTRU
Challenge = ntru.Ntru(7, 29, 491531)
Challenge.genPublicKey(priv_key_sf, priv_key_sg, 2)

# Client configuration
server_ip = "192.168.68.139"
server_port = 4449
client_ip = "192.168.68.143"


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


bind_layers(IP, EncryptedTCP, proto=99)


def sign_fn(payload, qrng, header):
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
    jv = [b64encode(x).decode('utf-8') for x in (qrng, header, ciphertext, tag)]
    result = json.dumps(dict(zip(jk, jv)))
    return result


def check_signature(payload):
    try:
        b64 = json.loads(payload)
        jk = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in jk}

        cipher = ChaCha20_Poly1305.new(key=shared_secret, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

        blockhash, sign_str, pk_arr, server_qrng = plaintext.split(b'<|>')
        sign_str = bytes(sign_str)
        print("Decrypted hash: ", blockhash)

        pk_fn = falcon.PublicKey(n=32, h=list(struct.unpack('>' + 'h' * (len(pk_arr) // 2), pk_arr)))
        check = pk_fn.verify(blockhash, bytes(sign_str))
        print("Verification status: " + str(check))

        return blockhash, check, server_qrng
    except (ValueError, KeyError):
        print("Incorrect decryption")
        return None, False, None


from scapy.all import *
import time

def send_with_timeout(pkt, filter_str, timeout=10, retry=1):
    for _ in range(retry + 1):  # Original attempt + retry
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is not None:
            return ans
        print(f"No response received within {timeout} seconds. Retrying...")
    print("No response received after retry. Continuing...")
    return None


# Main client logic
print("Client initializing...")
client_port = random.randint(1024, 65535)
ip_pkt = IP(dst=server_ip, proto=99)

# Initiate TCP handshake
syn = ip_pkt / EncryptedTCP(flags="S", reserved=7)
syn_ack = sr1(syn)
ack = ip_pkt / EncryptedTCP(flags="A", ack=syn_ack.seq + 1)
send(ack)
print("TCP Handshake completed")

# Receive server's public key
msg1 = sniff(filter=f"ip and src {server_ip}", count=1)[0]
if len(msg1[Raw].load) > 0:
    params, pub_key = msg1[Raw].load.split(b'|')
    N, p, q = map(int, params.decode().split(','))
    pub_key = ast.literal_eval(pub_key.decode("UTF-8"))
    print("Parameters Received from Server: ", N, p, q)
    print("Public Key Received from Server: ", pub_key)

    # Create NTRU instance and set public key
    Alice = ntru.Ntru(N, p, q)
    Alice.setPublicKey(pub_key)

    # Generate and encrypt message
    message = [1, 1, 0, 0, 1, 0, 1]
    print("Client's Original Message: ", message)
    ranPol = [-1, -1, 1, 1]
    reply1 = Alice.encrypt(message, ranPol)
    print("Encrypted Message: ", reply1)

    # Send encrypted message to server
    pkt1 = ip_pkt / EncryptedTCP(flags="PA") / str(reply1)
    send(pkt1)

    # Generate shared secret
    message = pad_message(bytes(message))
    shared_secret = bytes(haraka512256(message))
    print("Shared Secret: ", shared_secret)

    # Receive server's hash and client nonce
    msg2 = sniff(filter=f"ip and src {server_ip}", count=1)[0]
    server_hash, _, client_qrng = check_signature(msg2[Raw].load)
    print("Received client nonce from server: ", client_qrng)

    # Generate and send client's challenge
    client_challenge = [1, 0, 1, 0, 1, 1, 2]
    print("Client's Challenge: ", client_challenge)
    challenge_sum = sum(client_challenge)
    encrypted_challenge = Challenge.encrypt([challenge_sum],ranPol)

    # Convert the encrypted challenge to bytes
    encrypted_challenge_bytes = struct.pack(f'>{len(encrypted_challenge)}I', *encrypted_challenge)

    encrypted_challenge_base64 = base64.b64encode(encrypted_challenge_bytes).decode('utf-8')
    challenge_str = json.dumps({'ciphertext': encrypted_challenge_base64, 'sum': challenge_sum})
    print(f"Sending challenge: {challenge_str}")
    pkt_challenge = ip_pkt / EncryptedTCP(flags="PA") / challenge_str
    send(pkt_challenge)
    print("Encrypted challenge:", challenge_str)


    # Receive and verify server's solution
    challenge_response = sniff(filter=f"ip and src {server_ip}", count=1)[0]

    server_solution = json.loads(challenge_response[Raw].load)
    encrypted_solution_bytes = base64.b64decode(server_solution['ciphertext'])
    decrypted_response = Challenge.decrypt(list(encrypted_solution_bytes))

    print("Received encrypted solution:", server_solution['ciphertext'])
    # decrypted_response = Challenge.decrypt(ast.literal_eval(server_solution['ciphertext']))
    print("Decrypted server's solution:", decrypted_response)
    expected_solution = sum(client_challenge)
    print("Expected solution:", expected_solution)
    if decrypted_response[0] == expected_solution:
        print("Server successfully solved the challenge")
    else:
        print(f"Server failed to solve the challenge. Got {decrypted_response[0]}, expected {expected_solution}")
        # exit()

    # Receive server's challenge
    server_challenge = sniff(filter=f"ip and src {server_ip}", count=1)[0]
    server_challenge_data = json.loads(server_challenge[Raw].load)
    decrypted_server_challenge = Challenge.decrypt(ast.literal_eval(server_challenge_data['ciphertext']))
    print("Decrypted Server Challenge: ", decrypted_server_challenge)

    # Solve and send response to server's challenge
    server_challenge_solution = [1]
    for num in decrypted_server_challenge:
        server_challenge_solution[0] *= num
    encrypted_server_solution = Challenge.encrypt(server_challenge_solution, ranPol)
    server_solution_str = json.dumps({'ciphertext': str(encrypted_server_solution)})
    pkt_server_solution = ip_pkt / EncryptedTCP(flags="PA") / server_solution_str
    send(pkt_server_solution)

    # Send client's hash
    msg3 = json.dumps(pub_key)
    msg3 = bytes(msg3, 'utf-8')
    msg3 = sign_fn(msg3, header=b"client_hash", qrng=client_qrng)
    pkt2 = ip_pkt / EncryptedTCP(flags="PA") / msg3
    send(pkt2)

    # Receive server's acknowledgment
    ack = sniff(filter=f"ip and src {server_ip}", count=1)[0]
    print("Challenge-response completed, starting communication with server")

    # Main communication loop
    while True:
        user_msg = input("Enter a message to send to the server (or 'bye' to exit): ")
        if user_msg.lower() == 'bye':
            fin = IP(dst=server_ip) / EncryptedTCP(flags="FA")
            send(fin)
            fin_ack = sniff(filter=f"ip and src {server_ip}", count=1)[0]
            ack_fin = IP(dst=server_ip) / EncryptedTCP(flags="A")
            send(ack_fin)
            break

        user_msg_enc = sign_fn(user_msg.encode(), header=b"data_exchange", qrng=client_qrng)
        pkt3 = IP(dst=server_ip) / EncryptedTCP(flags="PA") / user_msg_enc
        send(pkt3)

        reply = sniff(filter=f"ip and src {server_ip}", count=1)[0]
        reply_dec, verif, server_qrng = check_signature(reply[Raw].load)
        if verif:
            print("Reply from server:", reply_dec.decode("UTF-8"))
        else:
            print("Failed to verify server's message")

else:
    print("Error: No data received from server")