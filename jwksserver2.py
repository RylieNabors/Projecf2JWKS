import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

hostName = "localhost"
serverPort = 8080

def create_key(expiration_time):
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	# functions to serialize the key to PKCS#1 (TraditionalOpenSSL)
	pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)

	# save key into values
	# kid is filled automatically with an integer since its set to an INTEGER PRIMARY KEY
	# "with conn" eliminates need for commit
	with conn:
		t.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (pem, expiration_time))

def int_to_base64(value):
	"""Convert an integer to a Base64URL-encoded string"""
	value_hex = format(value, 'x')
	# Ensure even length
	if len(value_hex) % 2 == 1:
		value_hex = '0' + value_hex
	value_bytes = bytes.fromhex(value_hex)
	encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
	return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
	def do_PUT(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_PATCH(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_DELETE(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_HEAD(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_POST(self):
		parsed_path = urlparse(self.path)
		params = parse_qs(parsed_path.query)
		if parsed_path.path == "/auth":
			current_time = int(datetime.datetime.now().timestamp())
			if 'expired' in params:
				c = t.execute("SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
			else:
				c = t.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))

			# get pem from database
			foundKey = c.fetchone()

			if foundKey:
				pem = foundKey[0]
				private_key = serialization.load_pem_private_key(pem, password=None) 

			headers = {
				"kid": "goodKID"
			}
			token_payload = {
				"user": "username",
				"exp": datetime.datetime.now() + datetime.timedelta(hours=1)
			}
			if 'expired' in params:
				headers["kid"] = "expiredKID"
				token_payload["exp"] = datetime.datetime.now() - datetime.timedelta(hours=1)
			encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
			self.send_response(200)
			self.end_headers()
			self.wfile.write(bytes(encoded_jwt, "utf-8"))
			return

		self.send_response(405)
		self.end_headers()
		return

	def do_GET(self):
		if self.path == "/.well-known/jwks.json":
			current_time = int(datetime.datetime.now().timestamp())
			c = t.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))

			# Construct JWKS response
			keys = {"keys": []}
			for row in c.fetchall():
				pem = row[0]
				private_key = serialization.load_pem_private_key(pem, password=None)
				public_key = private_key.public_key()
				numbers = public_key.public_numbers()

				keys["keys"].append({
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"kid": "goodKID",  # Use a method to set appropriate Key ID
					"n": int_to_base64(numbers.n),
					"e": int_to_base64(numbers.e)
				})

			# Return the JWKS
			self.send_response(200)
			self.send_header("Content-Type", "application/json")
			self.end_headers()
			self.wfile.write(bytes(json.dumps(keys), "utf-8"))
			return

		self.send_response(405)
		self.end_headers()
		return


if __name__ == "__main__":
	webServer = HTTPServer((hostName, serverPort), MyServer)

	# create connection to database
	conn = sqlite3.connect('totally_not_my_privateKeys.db')

	# create cursor so that we can use execute method to make SQL commands
	t = conn.cursor()

	# creates table in database if it doesn't already exist
	t.execute("""CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)""")

	# commit command
	conn.commit()

	# save pem to database rather than making it a global variable
	# unexpired key
	unexpired_time = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
	create_key(unexpired_time)
	# expired key
	expired_time = int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp())
	create_key(expired_time)

	try:
		webServer.serve_forever()
	except KeyboardInterrupt:
		pass

	# close connection
	conn.close()
	webServer.server_close()
