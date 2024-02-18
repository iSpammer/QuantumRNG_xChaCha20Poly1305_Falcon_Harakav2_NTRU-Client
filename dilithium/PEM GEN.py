import base64

import numpy as np
from OpenSSL import crypto

from dilithium import Dilithium2
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
from dilithium import Dilithium2


import numpy as np




# Import cffi module
import cffi
ffi = cffi.FFI()

# Convert byte objects to cdata pointers
server_country = ffi.new("unsigned char []", b"EG")
server_state_code = ffi.new("unsigned char []", b"EG")
server_state = ffi.new("unsigned char []", b"CAIRO")
server_org = ffi.new("unsigned char []", b"OSSTECH")
server_org_unit = ffi.new("unsigned char []", b"RND")
server_cname = ffi.new("unsigned char []", b"server")
server_email = ffi.new("unsigned char []", b"server.osstech.com.eg")

# Import numpy and Dilithium modules
import numpy as np
from dilithium import Dilithium

# Define the message as a numpy array

# Generate a bit-packed keypair using Dilithium.keygen()
pk, sk = Dilithium2.keygen()
msg = np.array([server_country, server_state_code, server_state, server_org, server_org_unit, server_cname, server_email, pk])

msg = msg.tobytes()


# Generate a bit-packed signature using Dilithium.sign()
sig = Dilithium2.sign(sk, msg)

# Create a certificate object using OpenSSL.crypto module
cert = crypto.X509()

# Set the subject and issuer fields of the certificate using the message array
cert.get_subject().C = server_country # Country
cert.get_subject().ST = server_state_code # State code
cert.get_subject().L = server_state # State
cert.get_subject().O = server_org # Organization
cert.get_subject().OU = server_org_unit # Organization unit
cert.get_subject().CN = server_cname # Common name
cert.get_subject().emailAddress = server_email # Email address

# Set the issuer field to be the same as the subject (self-signed certificate)
cert.set_issuer(cert.get_subject())

# Set the public key field of the certificate using the bit-packed public key
cert.set_pubkey(crypto.load_publickey(crypto.FILETYPE_ASN1, pk))

# Set the serial number and validity period of the certificate
cert.set_serial_number(1)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10*365*24*60*60) # 10 years

# Sign the certificate using the bit-packed signature
cert.sign(crypto.load_privatekey(crypto.FILETYPE_ASN1, sk), sig)

# Export the certificate and the private key as .pem files
with open("ca_cert.pem", "wb") as f:
    f.write(cert.export(crypto.FILETYPE_PEM))

with open("ca_key.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cert.get_pubkey()))
