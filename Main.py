import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as pad
import os
import requests

import socket

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def getPK(Path):
    with open(Path, "rb") as key_file:
        PK = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    if isinstance(PK, rsa.RSAPublicKey):
        return PK
    else:
        return None


def layer(PK, data):
    key1 = os.urandom(16)
    iv1 = os.urandom(16)
    Key_iv1 = key1 + iv1

    cipher = Cipher(algorithms.AES(key1), modes.CBC(iv1), backend=default_backend())
    encryptor = cipher.encryptor()



    if isinstance(data, str):
        padder = pad.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(str.encode(data)) + padder.finalize()
        AES_ct = encryptor.update(padded_data) + encryptor.finalize()
    else:
        padder = pad.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        AES_ct = encryptor.update(padded_data) + encryptor.finalize()

    RSA_ct = PK.encrypt(
        Key_iv1,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return RSA_ct + AES_ct



print("Starting")

recipient = "Bob"
message = "This is a message from group 2"
data = recipient + "," + message

port = "55409"
url = "pets.ewi.utwente.nl:" + port

PK1 = getPK("key_files/public-key-mix-1.pem")
PK2 = getPK("key_files/public-key-mix-2.pem")
PK3 = getPK("key_files/public-key-mix-3.pem")

E1 = layer(PK3, data)
E2 = layer(PK2, E1)
E3 = layer(PK1, E2)

length = bytearray.fromhex('{:08x}'.format(len(E3)))
network_message = length + E3

print('network_message:', ''.join('{: 02x}'.format(x) for x in network_message))

# r = requests.post("http://bugs.python.org", data=network_message, stream=True)
# print(r.status_code, r.reason)
# print(r.raw.read(100))


clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect(('pets.ewi.utwente.nl', 57663))
clientsocket.send(network_message)
print(clientsocket.recv(1024))
print("Done!")
