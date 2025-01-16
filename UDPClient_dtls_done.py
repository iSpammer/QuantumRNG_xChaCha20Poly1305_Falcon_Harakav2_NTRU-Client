#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import time
import hmac
import struct
import traceback
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from scapy.all import *
from scapy.layers.inet import UDP, IP
import ast

from CA_CONNECTION import request_handler
from harakav2 import pad_message, haraka512256
from falcon import falcon
from NTRU import ntru
import numpy as np
from blockchain2 import *


# dtls_constants.py

# Content Types
class ContentType:
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


# Handshake Message Types
class HandshakeType:
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

    @staticmethod
    def get_name(msg_type):
        types = {
            0: "HELLO_REQUEST",
            1: "CLIENT_HELLO",
            2: "SERVER_HELLO",
            3: "HELLO_VERIFY_REQUEST",
            11: "CERTIFICATE",
            12: "SERVER_KEY_EXCHANGE",
            13: "CERTIFICATE_REQUEST",
            14: "SERVER_HELLO_DONE",
            15: "CERTIFICATE_VERIFY",
            16: "CLIENT_KEY_EXCHANGE",
            20: "FINISHED"
        }
        return types.get(msg_type, f"UNKNOWN({msg_type})")


# Protocol Versions
class ProtocolVersion:
    DTLS_1_0 = b'\xfe\xff'
    DTLS_1_2 = b'\xfe\xfd'


# Alert Types
class AlertType:
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    HANDSHAKE_FAILURE = 40
    CERTIFICATE_EXPIRED = 45
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    INSUFFICIENT_SECURITY = 71


# Cipher Suites
class CipherSuite:
    TLS_RSA_WITH_AES_128_CBC_SHA = b'\x00\x2F'
    TLS_RSA_WITH_AES_256_CBC_SHA = b'\x00\x35'


# Record Layer Constants
class RecordLayer:
    HEADER_LENGTH = 13  # DTLS record header length
    MAX_FRAGMENT_LENGTH = 2 ** 14  # Maximum fragment length
    SEQUENCE_NUMBER_LENGTH = 8  # 8 bytes for epoch (2) + sequence number (6)


# Handshake Constants
class HandshakeLayer:
    HEADER_LENGTH = 12  # DTLS handshake header length
    MAX_FRAGMENT_LENGTH = 2 ** 14  # Maximum handshake fragment length
    CLIENT_RANDOM_LENGTH = 32
    SERVER_RANDOM_LENGTH = 32
    SESSION_ID_MAX_LENGTH = 32
    VERIFY_DATA_LENGTH = 12  # Length of verify data in Finished message


# Cookie Constants
class CookieSettings:
    MIN_LENGTH = 1
    MAX_LENGTH = 32
    DEFAULT_LIFETIME = 60  # seconds


# Timeouts and Retransmission
class TimeoutSettings:
    INITIAL_TIMEOUT = 1.0  # seconds
    MAX_TIMEOUT = 60.0  # seconds
    MAX_TRANSMISSIONS = 5


class BlockchainCertificateHandler:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache

    def verify_certificate(self, cert_data, block_hash):
        """Verify certificate using blockchain"""
        # Check cache first
        cache_key = f"{cert_data['pub_key_s_h']}:{block_hash}"
        if cache_key in self.cache:
            cache_time, result = self.cache[cache_key]
            if time.time() - cache_time < self.cache_ttl:
                return result

        # Verify on blockchain
        try:
            # Get certificate block from blockchain
            cert_block = self._get_certificate_block(block_hash)
            if not cert_block:
                return False

            # Verify certificate data matches blockchain record
            if not self._verify_cert_data(cert_data, cert_block):
                return False

            # Verify block proof of work
            if not self.blockchain.proof_of_work(cert_block):
                return False

            # Cache result
            self.cache[cache_key] = (time.time(), True)
            return True

        except Exception as e:
            print(f"Certificate verification error: {e}")
            return False

    def _get_certificate_block(self, block_hash):
        """Get certificate block from blockchain"""
        for block in self.blockchain.chain:
            if block.hashid == block_hash:
                return block
        return None

    def _verify_cert_data(self, cert_data, cert_block):
        """Verify certificate data matches blockchain record"""
        block_cert = cert_block.transactions
        required_fields = ['country', 'state', 'org', 'cname', 'pub_key_s_h']

        for field in required_fields:
            if cert_data.get(field) != block_cert.get(field):
                return False

        return True


class DTLSError(Exception):
    """Base class for DTLS protocol errors"""
    pass


class DTLSTimeout(DTLSError):
    """Raised when a DTLS operation times out"""
    pass


class DTLSVerificationError(DTLSError):
    """Raised when message verification fails"""
    pass


class DTLSRecordLayer:
    """DTLS Record Layer handling"""

    def __init__(self):
        self.epoch = 0
        self.sequence_number = 0

    def create_record_header(self, content_type, length):
        """Create DTLS record layer header"""
        return (
                bytes([content_type]) +
                ProtocolVersion.DTLS_1_2 +  # Instead of b'\xfe\xfd'
                struct.pack("!H", self.epoch) +
                struct.pack("!Q", self.sequence_number)[:6] +
                struct.pack("!H", length)
        )

    def increment_seq(self):
        self.sequence_number += 1
        if self.sequence_number >= 2 ** 48:
            raise ValueError("Sequence number overflow")

    def new_epoch(self):
        self.epoch += 1
        if self.epoch >= 2 ** 16:
            raise ValueError("Epoch overflow - need new connection")
        self.sequence_number = 0


class DTLSHandshake:
    def __init__(self, record_layer, cert_handler):
        self.message_seq = 0
        self.client_random = None
        self.server_random = None
        self.session_id = os.urandom(32)
        self.record_layer = record_layer
        self.cert_handler = cert_handler
        self.handshake_messages = []  # For verification
        self.cipher_suites = [
            b'\x00\x2F',  # TLS_RSA_WITH_AES_128_CBC_SHA
            b'\x00\x35'  # TLS_RSA_WITH_AES_256_CBC_SHA
        ]

    def parse_server_hello(self, handshake_data):
        """Parse ServerHello message"""
        try:
            # Skip handshake header (12 bytes)
            hello_body = handshake_data[12:]
            if len(hello_body) < 34:
                print("ServerHello body too short")
                return False

            server_version = hello_body[:2]
            server_random = hello_body[2:34]
            session_id_length = hello_body[34]
            cipher_suite_offset = 35 + session_id_length

            if len(hello_body) < cipher_suite_offset + 2:
                print("ServerHello too short for cipher suite")
                return False

            # Store server random
            self.server_random = server_random

            print(f"Parsed ServerHello:")
            print(f"Version: {server_version.hex()}")
            print(f"Server Random: {server_random.hex()}")
            if session_id_length > 0:
                session_id = hello_body[35:35 + session_id_length]
                print(f"Session ID: {session_id.hex()}")
            print(f"Cipher Suite: {hello_body[cipher_suite_offset:cipher_suite_offset + 2].hex()}")

            return True

        except Exception as e:
            print(f"Error parsing ServerHello: {e}")
            traceback.print_exc()
            return False

    # In DTLSHandshake class
    def create_client_hello(self, cookie=b''):
        """Create ClientHello message"""
        try:
            # Generate and store client random if not already set
            if not self.client_random:  # Changed from self.handshake.client_random
                self.client_random = os.urandom(HandshakeLayer.CLIENT_RANDOM_LENGTH)

            # ClientHello body
            hello_body = (
                    ProtocolVersion.DTLS_1_2 +  # DTLS version
                    self.client_random +  # Changed from self.handshake.client_random
                    b'\x00' +  # Session ID length (0)
                    struct.pack("!B", len(cookie)) +  # Cookie length
                    cookie +  # Cookie
                    struct.pack("!H", len(self.cipher_suites) * 2) +  # Cipher suites length
                    b''.join(self.cipher_suites) +  # Cipher suites
                    b'\x01\x00'  # Compression methods
            )

            # Create handshake header
            handshake = self.create_handshake_header(
                msg_type=HandshakeType.CLIENT_HELLO,
                length=len(hello_body),
                seq=0
            ) + hello_body

            # Create record header
            record = self.record_layer.create_record_header(
                content_type=ContentType.HANDSHAKE,
                length=len(handshake)
            )

            return record + handshake
        except Exception as e:
            print(f"Error creating ClientHello: {e}")
            traceback.print_exc()
            return None

    def create_handshake_header(self, msg_type, length, seq=None, frag_offset=0):
        """Create DTLS handshake header with sequence tracking"""
        if seq is None:
            seq = self.message_seq
            self.message_seq += 1

        header = (
                bytes([msg_type]) +  # Handshake type
                struct.pack("!I", length)[1:] +  # Length (24-bit)
                struct.pack("!H", seq) +  # Message sequence
                struct.pack("!I", frag_offset)[1:] +  # Fragment offset (24-bit)
                struct.pack("!I", length)[1:]  # Fragment length (24-bit)
        )

        return header

    def process_handshake_message(self, data, expected_type):
        """Process incoming handshake message"""
        try:
            if len(data) < 12:  # Minimum handshake header size
                raise DTLSError("Handshake message too short")

            msg_type = data[0]
            msg_len = struct.unpack("!I", b'\x00' + data[1:4])[0]
            msg_seq = struct.unpack("!H", data[4:6])[0]
            frag_offset = struct.unpack("!I", b'\x00' + data[6:9])[0]
            frag_len = struct.unpack("!I", b'\x00' + data[9:12])[0]

            if msg_type != expected_type:
                raise DTLSError(f"Unexpected message type: {msg_type}, expected: {expected_type}")

            # Store message for finished verification
            self.handshake_messages.append(data)

            return data[12:12 + msg_len]  # Return message body

        except Exception as e:
            raise DTLSError(f"Error processing handshake message: {e}")

    def create_change_cipher_spec(self):
        """Create ChangeCipherSpec message"""
        return self.record_layer.create_record_header(
            content_type=20,  # ChangeCipherSpec
            length=1
        ) + b'\x01'

    def create_finished(self, master_secret):
        """Create Finished message with proper verification"""
        verify_data = self.calculate_verify_data(master_secret)

        finished_msg = self.create_handshake_header(
            msg_type=20,  # Finished
            length=len(verify_data)
        ) + verify_data

        record = self.record_layer.create_record_header(
            content_type=22,  # Handshake
            length=len(finished_msg)
        ) + finished_msg

        return record

    def calculate_verify_data(self, master_secret):
        """Calculate verify_data for Finished message"""
        if not self.handshake_messages:
            raise DTLSError("No handshake messages to verify")

        # Concatenate all handshake messages
        messages = b''.join(self.handshake_messages)

        # Calculate verify data using PRF
        verify_data = self.prf(
            master_secret,
            b'client finished' if self.is_client else b'server finished',
            messages,
            12  # verify_data length
        )

        return verify_data

    def prf(self, secret, label, seed, length):
        """DTLS PRF implementation"""
        # Implementation of TLS 1.2 PRF using SHA-256
        hmac_sha256 = lambda key, msg: hmac.new(key, msg, hashlib.sha256).digest()

        # P_hash implementation
        def p_hash(secret, seed, length):
            result = b''
            a = seed
            while len(result) < length:
                a = hmac_sha256(secret, a)
                result += hmac_sha256(secret, a + seed)
            return result[:length]

        return p_hash(secret, label + seed, length)


class DTLSClient:
    """DTLS Client implementation"""

    def __init__(self, server_ip, server_port):
        # Load client certificate and keys
        self.data_client = np.load('client_cert.npy', allow_pickle='TRUE').item()
        self.pub_key = self.data_client['pub_key_s_h']
        self.priv_key_sf = self.data_client['sk_f']
        self.priv_key_sg = self.data_client['sk_g']

        # Connection parameters
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = random.randint(1024, 65535)

        # Initialize blockchain
        self.blockchain = Blockchain(difficulty=20)

        # Initialize certificate handler
        self.cert_handler = BlockchainCertificateHandler(self.blockchain)

        # Initialize DTLS components with cert handler
        self.record_layer = DTLSRecordLayer()
        self.handshake = DTLSHandshake(self.record_layer, self.cert_handler)

        self.shared_secret = None

        # Initialize NTRU
        self.challenge = ntru.Ntru(7, 29, 491531)
        self.challenge.genPublicKey(self.priv_key_sf, self.priv_key_sg, 2)

        print(f"DTLS Client initialized, using port {self.client_port}")

    # In your DTLSClient class
    def send_packet(self, data, timeout=5):  # Increased timeout
        try:
            print(f"Sending packet ({len(data)} bytes):")
            print(f"First 13 bytes (record header): {data[:13].hex()}")

            pkt = IP(dst=self.server_ip) / UDP(
                sport=self.client_port,
                dport=self.server_port
            ) / Raw(data)

            send(pkt)

            # Wait for response with more debug info
            response = sniff(
                filter=f"udp src port {self.server_port} and dst port {self.client_port}",
                timeout=timeout,
                count=1
            )

            if response:
                print("Received response")
                if Raw in response[0]:
                    print(f"Response data: {response[0][Raw].load.hex()}")
                return response[0]
            print("No response received")
            return None

        except Exception as e:
            print(f"Error sending packet: {e}")
            return None

    def perform_handshake(self):
        """Perform DTLS handshake"""
        try:
            # Initial ClientHello (without cookie)
            print("\nSending initial ClientHello")
            initial_hello = self.handshake.create_client_hello()
            if not initial_hello:
                print("Failed to create initial ClientHello")
                return False

            print(f"Sending packet length: {len(initial_hello)} bytes")
            response = self.send_packet(initial_hello)

            if not response or not Raw in response:
                print("No response to initial ClientHello")
                return False

            # Process HelloVerifyRequest and continue handshake...
            return self.process_hello_verify_request(response)

        except Exception as e:
            print(f"Handshake error: {e}")
            traceback.print_exc()
            return False

    def process_hello_verify_request(self, response):
        """Process HelloVerifyRequest message and continue handshake"""
        try:
            if not Raw in response:
                print("No data in HelloVerifyRequest response")
                return False

            raw_data = response[Raw].load
            print(f"\nReceived HelloVerifyRequest ({len(raw_data)} bytes):")
            print(f"Raw data: {raw_data.hex()}")

            # Parse record header
            content_type = raw_data[0]
            version = raw_data[1:3]
            epoch = raw_data[3:5]
            seq_num = raw_data[5:11]
            length = struct.unpack("!H", raw_data[11:13])[0]

            print("\nRecord Layer Header:")
            print(f"Content Type: {content_type}")
            print(f"Version: {version.hex()}")
            print(f"Epoch: {epoch.hex()}")
            print(f"Sequence: {seq_num.hex()}")
            print(f"Length: {length}")

            if content_type != 22:  # Handshake
                print(f"Unexpected content type: {content_type}")
                return False

            # Parse handshake header
            handshake_data = raw_data[13:]
            if len(handshake_data) < 12:
                print("Data too short for handshake header")
                return False

            msg_type = handshake_data[0]
            if msg_type != 3:  # HelloVerifyRequest
                print(f"Unexpected handshake type: {msg_type}")
                return False

            # Extract cookie
            hello_verify_body = handshake_data[12:]
            if len(hello_verify_body) < 3:
                print("HelloVerifyRequest body too short")
                return False

            server_version = hello_verify_body[:2]
            cookie_length = hello_verify_body[2]
            cookie = hello_verify_body[3:3 + cookie_length]

            print("\nHelloVerifyRequest Body:")
            print(f"Server Version: {server_version.hex()}")
            print(f"Cookie Length: {cookie_length}")
            print(f"Cookie: {cookie.hex()}")

            # Send new ClientHello with cookie
            print("\nSending ClientHello with cookie")
            hello_with_cookie = self.handshake.create_client_hello(cookie)
            if not hello_with_cookie:
                print("Failed to create ClientHello with cookie")
                return False

            response = self.send_packet(hello_with_cookie)
            if not response:
                print("No response to ClientHello with cookie")
                return False

            # Process server flight
            return self.process_server_messages()

        except Exception as e:
            print(f"Error processing HelloVerifyRequest: {e}")
            traceback.print_exc()
            return False

    def parse_server_hello(self, handshake_data):
        """Parse ServerHello message"""
        try:
            # Skip handshake header (12 bytes)
            hello_body = handshake_data[12:]
            if len(hello_body) < 34:
                print("ServerHello body too short")
                return False

            server_version = hello_body[:2]
            server_random = hello_body[2:34]
            session_id_length = hello_body[34]
            cipher_suite_offset = 35 + session_id_length

            if len(hello_body) < cipher_suite_offset + 2:
                print("ServerHello too short for cipher suite")
                return False

            # Store server random
            self.server_random = server_random

            print(f"Parsed ServerHello:")
            print(f"Version: {server_version.hex()}")
            print(f"Server Random: {server_random.hex()}")
            if session_id_length > 0:
                session_id = hello_body[35:35 + session_id_length]
                print(f"Session ID: {session_id.hex()}")
            print(f"Cipher Suite: {hello_body[cipher_suite_offset:cipher_suite_offset + 2].hex()}")

            return True

        except Exception as e:
            print(f"Error parsing ServerHello: {e}")
            traceback.print_exc()
            return False

    def process_server_messages(self):
        """Process all server flight messages"""
        try:
            print("\nWaiting for server's flight of messages")

            # Track received message types
            server_hello_received = False
            certificate_received = False
            server_hello_done_received = False

            start_time = time.time()
            timeout = 5  # Timeout in seconds

            while not (server_hello_received and certificate_received and server_hello_done_received) and (time.time() - start_time) < timeout:
                messages = sniff(
                    filter=f"udp src port {self.server_port} and dst port {self.client_port}",
                    count=1,
                    timeout=5  # Timeout for each sniff call
                )

                if messages:
                    if Raw in messages[0]:
                        pkt = messages[0]
                        data = pkt[Raw].load
                        if len(data) < RecordLayer.HEADER_LENGTH:
                            continue

                        content_type = data[0]
                        if content_type != ContentType.HANDSHAKE:
                            continue

                        handshake_data = data[RecordLayer.HEADER_LENGTH:]
                        if len(handshake_data) < HandshakeLayer.HEADER_LENGTH:
                            continue

                        msg_type = handshake_data[0]
                        print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")

                        if msg_type == HandshakeType.SERVER_HELLO:
                            print("Processing ServerHello...")
                            if self.parse_server_hello(handshake_data):
                                server_hello_received = True
                                print("ServerHello processed successfully")

                        elif msg_type == HandshakeType.CERTIFICATE:
                            print("Processing Certificate...")
                            if self.process_server_certificate(handshake_data):
                                certificate_received = True
                                print("Certificate processed successfully")

                        elif msg_type == HandshakeType.SERVER_HELLO_DONE:
                            print("Processing ServerHelloDone...")
                            server_hello_done_received = True
                            print("ServerHelloDone processed successfully")

            # Verify we received all required messages
            if not (server_hello_received and certificate_received and server_hello_done_received):
                print("\nError: Missing required server messages:")
                print(f"ServerHello received: {server_hello_received}")
                print(f"Certificate received: {certificate_received}")
                print(f"ServerHelloDone received: {server_hello_done_received}")
                return False

            print("\nServer flight processed successfully")
            return True

        except Exception as e:
            print(f"Error processing server messages: {e}")
            traceback.print_exc()
            return False
    def process_server_flight(self):
        """Process server's flight of handshake messages"""
        try:
            print("\nWaiting for server's flight of messages")

            # Collect all flight messages with proper timing
            server_messages = []

            # Sniff for flight messages with timeout
            messages = sniff(
                filter=f"udp src port {self.server_port} and dst port {self.client_port}",
                timeout=5,
                count=3  # ServerHello, Certificate, ServerHelloDone
            )

            if not messages:
                print("No server flight messages received")
                return False

            server_messages.extend(messages)
            print(f"\nReceived {len(server_messages)} messages from server")

            # Process messages in sequence
            server_hello_received = False
            certificate_received = False
            server_hello_done_received = False

            for pkt in server_messages:
                if not Raw in pkt:
                    continue

                data = pkt[Raw].load
                if len(data) < 13:  # Minimum record header length
                    continue

                content_type = data[0]
                if content_type != 22:  # Not handshake
                    continue

                handshake_data = data[13:]
                if len(handshake_data) < 12:  # Minimum handshake header
                    continue

                msg_type = handshake_data[0]
                print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")


                if msg_type == 2:  # ServerHello
                    print("Processing ServerHello...")
                    if self.process_server_hello(handshake_data):
                        server_hello_received = True
                        print("ServerHello processed successfully")

                elif msg_type == 11:  # Certificate
                    print("Processing Certificate...")
                    if self.process_server_certificate(handshake_data):
                        certificate_received = True
                        print("Certificate processed successfully")

                elif msg_type == 14:  # ServerHelloDone
                    print("Processing ServerHelloDone")
                    server_hello_done_received = True
                    print("ServerHelloDone processed successfully")

            # Verify all messages received
            print("\nServer flight status:")
            print(f"ServerHello received: {server_hello_received}")
            print(f"Certificate received: {certificate_received}")
            print(f"ServerHelloDone received: {server_hello_done_received}")

            if not all([server_hello_received, certificate_received, server_hello_done_received]):
                print("Missing required server messages")
                return False

            print("\nServer flight processed successfully")
            return self.send_client_flight()

        except Exception as e:
            print(f"Error processing server flight: {e}")
            traceback.print_exc()
            return False

    def process_server_hello(self, handshake_data):
        """Process ServerHello message"""
        try:
            print("\nProcessing ServerHello details:")
            # Skip handshake header (12 bytes)
            hello_body = handshake_data[12:]
            if len(hello_body) < 34:
                print("ServerHello body too short")
                return False

            server_version = hello_body[:2]
            server_random = hello_body[2:34]
            self.handshake.server_random = server_random

            print(f"Server Version: {server_version.hex()}")
            print(f"Server Random: {server_random.hex()}")
            return True

        except Exception as e:
            print(f"Error processing ServerHello: {e}")
            traceback.print_exc()
            return False

    def process_server_certificate(self, handshake_data):
        """Process server certificate from handshake data"""
        try:
            print("\nProcessing server certificate...")
            # Skip handshake header (12 bytes) to get to certificate data
            cert_data = handshake_data[12:]

            # Parse certificate data
            try:
                cert_json = cert_data.decode('utf-8')
                cert_info = json.loads(cert_json)
                print(f"Received certificate data: {cert_info}")

                # Store certificate for later verification
                self.server_certificate = cert_info
                return True

            except json.JSONDecodeError as e:
                print(f"Error decoding certificate JSON: {e}")
                print(f"Raw certificate data: {cert_data}")
                return False

        except Exception as e:
            print(f"Error processing server certificate: {e}")
            traceback.print_exc()
            return False

    def process_server_hello(self, handshake_data):
        """Process ServerHello message"""
        try:
            print("\nProcessing ServerHello...")
            # Skip handshake header (12 bytes)
            hello_body = handshake_data[12:]

            if len(hello_body) < 34:  # Minimum ServerHello body length
                print("ServerHello message too short")
                return False

            # Extract ServerHello data
            server_version = hello_body[:2]
            server_random = hello_body[2:34]

            # Store server random for later use
            self.handshake.server_random = server_random

            print(f"Server Version: {server_version.hex()}")
            print(f"Server Random: {server_random.hex()}")

            return True

        except Exception as e:
            print(f"Error processing ServerHello: {e}")
            traceback.print_exc()
            return False

    def send_client_flight(self):
        """Send client's flight of messages"""
        try:
            print("\nPreparing client flight...")

            # Send Certificate
            print("Sending Certificate...")
            cert_record = self.create_client_certificate()
            response = self.send_packet(cert_record)
            if not response:
                print("No response to Certificate")
                return False
            time.sleep(0.2)  # Small delay between messages

            # Send ClientKeyExchange
            print("Sending ClientKeyExchange...")
            key_exchange = self.create_client_key_exchange()
            response = self.send_packet(key_exchange)
            if not response:
                print("No response to ClientKeyExchange, retrying")
                response = self.send_packet(key_exchange)
                if not response:
                    return False
            time.sleep(0.2)

            # Send ChangeCipherSpec
            print("Sending ChangeCipherSpec...")
            change_cipher_spec = self.record_layer.create_record_header(
                content_type=20,  # ChangeCipherSpec
                length=1
            ) + b'\x01'  # Change cipher spec message

            self.record_layer.new_epoch()  # Increment epoch before sending ChangeCipherSpec
            response = self.send_packet(change_cipher_spec)
            if not response:
                print("No response to ChangeCipherSpec")
                return False
            time.sleep(0.1)

            # Send Finished
            print("Sending Finished...")
            finished = self.create_finished_message()
            response = self.send_packet(finished)
            if not response:
                print("No response to Finished")
                return False

            # Process server's Finished message
            if not self.verify_server_finished(response):
                print("Failed to verify server's Finished message")
                return False

            print("Client flight completed successfully")
            return True

        except Exception as e:
            print(f"Error sending client flight: {e}")
            traceback.print_exc()
            return False

    def create_client_key_exchange(self):
        """Create ClientKeyExchange message with NTRU"""
        try:
            # Generate pre-master secret
            pre_master_secret = os.urandom(32)
            self.pre_master_secret = pre_master_secret  # Store for later use

            # Create random polynomial for NTRU encryption
            # For NTRU parameters N=7, d=2, a balanced polynomial with d 1's and d -1's
            randPol = [0] * 7  # length N=7
            # Place d 1's and d -1's randomly
            ones = [-1, -1, 1, 1]  # d=2 for each
            positions = random.sample(range(7), 4)  # 4 total positions (2 for 1's and 2 for -1's)
            for i, pos in enumerate(positions):
                randPol[pos] = ones[i]

            # Convert pre_master_secret to polynomial form
            # Each byte becomes a coefficient
            message_pol = []
            for b in pre_master_secret:
                message_pol.append(b % self.challenge.p)  # Reduce mod p
                if len(message_pol) >= 7:  # Keep within degree N-1
                    break
            while len(message_pol) < 7:
                message_pol.append(0)

            # Encrypt using NTRU
            encrypted_key = self.challenge.encrypt(message_pol, randPol)

            # Convert polynomial back to bytes
            encrypted_bytes = bytes(encrypted_key)

            # Create key exchange message
            key_msg = self.handshake.create_handshake_header(
                msg_type=HandshakeType.CLIENT_KEY_EXCHANGE,
                length=len(encrypted_bytes),
                seq=2
            ) + encrypted_bytes

            # Create record layer message
            record = self.record_layer.create_record_header(
                content_type=ContentType.HANDSHAKE,
                length=len(key_msg)
            ) + key_msg

            print(f"Created ClientKeyExchange ({len(record)} bytes)")
            print(f"KeyExchange content: {record.hex()}")
            return record

        except Exception as e:
            print(f"Error creating client key exchange: {e}")
            traceback.print_exc()
            return None

    def derive_master_secret(self):
        """Derive master secret using PRF"""
        try:
            if not self.pre_master_secret or not self.handshake.client_random or not self.handshake.server_random:
                raise DTLSError("Missing key material for master secret derivation")

            # Concatenate randoms for seed
            seed = self.handshake.client_random + self.handshake.server_random

            # Use PRF to generate master secret
            self.master_secret = self.handshake.prf(
                secret=self.pre_master_secret,
                label=b"master secret",
                seed=seed,
                length=48  # Standard master secret length
            )

            return True
        except Exception as e:
            print(f"Error deriving master secret: {e}")
            return False

    def verify_server_finished(self, response):
        """Verify server's Finished message"""
        try:
            if not Raw in response:
                return False

            data = response[Raw].load
            if len(data) < RecordLayer.HEADER_LENGTH:
                return False

            content_type = data[0]
            if content_type != ContentType.HANDSHAKE:
                return False

            handshake_data = data[RecordLayer.HEADER_LENGTH:]
            if len(handshake_data) < HandshakeLayer.HEADER_LENGTH:
                return False

            msg_type = handshake_data[0]
            print(f"\nProcessing message type {HandshakeType.get_name(msg_type)}")

            if msg_type != HandshakeType.FINISHED:
                return False

            # Extract verify data
            verify_data = handshake_data[HandshakeLayer.HEADER_LENGTH:]

            # Calculate expected verify data
            expected_verify_data = self.handshake.calculate_verify_data(
                self.master_secret,
                b'server finished',
                self.handshake.handshake_messages
            )

            if not hmac.compare_digest(verify_data, expected_verify_data):
                print("Server Finished verification failed")
                return False

            print("Server Finished message verified successfully")
            return True

        except Exception as e:
            print(f"Error verifying server Finished: {e}")
            traceback.print_exc()
            return False

    def create_client_certificate(self):
        """Create client certificate message"""
        try:
            cert_body = json.dumps(self.pub_key).encode()

            cert_msg = self.handshake.create_handshake_header(
                msg_type=11,  # Certificate
                length=len(cert_body),
                seq=1
            ) + cert_body

            record = self.record_layer.create_record_header(
                content_type=22,  # Handshake
                length=len(cert_msg)
            ) + cert_msg

            print(f"Created Certificate ({len(record)} bytes)")
            print(f"Certificate content: {record.hex()}")
            return record

        except Exception as e:
            print(f"Error creating client certificate: {e}")
            raise

    def create_finished_message(self):
        """Create Finished message"""
        # Generate verify data (in real DTLS this would be a PRF calculation)
        verify_data = os.urandom(HandshakeLayer.VERIFY_DATA_LENGTH)

        finished_msg = self.handshake.create_handshake_header(
            msg_type=HandshakeType.FINISHED,
            length=len(verify_data),
            seq=3
        ) + verify_data

        record = self.record_layer.create_record_header(
            content_type=ContentType.HANDSHAKE,
            length=len(finished_msg)
        ) + finished_msg

        return record

    def run(self):
        """Main client operation"""
        try:
            if self.perform_handshake():
                print("\nSecure connection established!")

                request_handler.get_request(server_ip="192.168.0.197", port=5000, server_pub=self.server_certificate)

                print(f'SERVER PKI VERIFIED SUCCESSFULLY')

                while True:
                    message = input("\nEnter message (or 'quit' to exit): ")
                    if message.lower() == 'quit':
                        break

                    # Send application data
                    encoded_message = message.encode()
                    record = self.record_layer.create_record_header(
                        content_type=23,  # Application Data
                        length=len(encoded_message)
                    ) + encoded_message

                    self.send_packet(record)
                    self.record_layer.increment_seq()

                    # Wait for server response
                    response = sniff(
                        filter=f"udp src port {self.server_port} and dst port {self.client_port}",
                        timeout=5,
                        count=1
                    )

                    if response and Raw in response[0]:
                        print(f"Server response: {response[0][Raw].load.decode()}")
                    else:
                        print("No response from server")

            print("\nConnection closed")

        except Exception as e:
            print(f"Error: {e}")
            print("Connection closed")


if __name__ == "__main__":
    client = DTLSClient("192.168.68.129", 4433)
    client.run()
