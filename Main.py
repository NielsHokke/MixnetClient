import base64

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os
import time
import urllib.request

def sendToServer(url, port, data):

	length = bytearray.fromhex('{:08x}'.format(len(data)))
	network_message = length + data

	try:
		clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		clientsocket.connect((url, port))
		clientsocket.send(network_message)
		data = clientsocket.recv(32)
	except:
		print("Failed to connect to server")
		# exit(0)

	# print(data)

	if data == b'\x06':
		pass
		# print("Message corectly recieved by Server")
	else:
		print("Failed to correctly send message")


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

	RSA_ct = PK.encrypt(
		IV_KEY,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)

	return RSA_ct + AES_ct


print("Starting")

inside = []
fh = open("result.csv", "w")


print("In; out; inside; delivered")
fh.write("In; out; inside; delivered \n")
for x in range(1,300 + 1):
	delivered = []
	recipient = "NHokke"
	message = str(x)
	data = recipient + "," + message
	inside.append(x)

	PK1 = getPK("key_files/public-key-mix-1.pem")
	PK2 = getPK("key_files/public-key-mix-2.pem")
	PK3 = getPK("key_files/public-key-mix-3.pem")

	E1 = layer(PK3, data)
	E2 = layer(PK2, E1)
	E3 = layer(PK1, E2)

	# print("Sending mesage: " + str(x))
	sendToServer("pets.ewi.utwente.nl", 56314 , E3)

	csv_url = 'https://pets.ewi.utwente.nl/log/2-uF6YF+Z9iMjHXW7wLdiwXo3MeKPaKp4xbSq/BqBzFnU=/exit.csv'

	outlog = urllib.request.urlopen(csv_url).read().decode("utf-8").split('\n')
	# print(outlog)

	for fullrow in outlog:
		row = fullrow.split(",")
		try:
			if "log" in row[0]:
				pass
			elif "PET" in row[1]:
				delivered.append('pet')
			else:
				out = int(row[2])
				inside = [x for x in inside if x != out]
				delivered.append(out)
		except:
			pass

	line = '{} ; {}; {} ; {} \n'.format(x, len(delivered), inside, delivered)
	print(line)
	fh.write(line)
	time.sleep(0.1)
	# print("\n")

print("Done!")
