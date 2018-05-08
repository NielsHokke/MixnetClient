import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as pad

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA



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
		print("Error reading RSA-Key from " + Path)
		return None


def layer(PK, data):
	key1 = os.urandom(16)
	iv1 = os.urandom(16)
	IV_KEY = iv1 + key1

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

	# RSA_ct = PK.encrypt(
	# 	IV_KEY,
	# 	padding.OAEP(
	# 		mgf=padding.MGF1(algorithm=hashes.SHA256()),
	# 		algorithm=hashes.SHA256(),
	# 		label=None
	# 	)
	# )

	key = RSA.importKey(open(PK).read())
	print(key)
	cipher = PKCS1_OAEP.new(key)
	RSA_ct = cipher.encrypt(IV_KEY)

	print(len(RSA_ct))
	print('RSA_ct:', ''.join('{: 02x}'.format(x) for x in RSA_ct))

	return RSA_ct + AES_ct


print("Starting")

recipient = "hendrik ido ambacht"
message = "This is a message from group 2"
data = recipient + "," + message

port = 59766
url = "pets.ewi.utwente.nl"

PK1 = "key_files/public-key-mix-1.pem"
PK2 = "key_files/public-key-mix-2.pem"
PK3 = "key_files/public-key-mix-3.pem"

E1 = layer(PK3, data)
E2 = layer(PK2, E1)
E3 = layer(PK1, E2)

length = bytearray.fromhex('{:08x}'.format(len(E3)))
network_message = length + E3

# print('network_message:', ''.join('{: 02x}'.format(x) for x in network_message))

try:
	clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientsocket.connect((url, port))
	clientsocket.send(network_message)
	data = clientsocket.recv(32)
except:
	print("Failed to connect to server")
	exit(0)

print(data)

if data == b'\x06':
	print("Message corectly recieved by Server")
else:
	print("Failed to correctly send message")


print("Done!")
