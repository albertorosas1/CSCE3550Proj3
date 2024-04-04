from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import base64
import json
import sqlite3
import time
import uuid
import datetime
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
#Import all our libraries needed for completing the project


NOT_MY_KEY = b'asry5x8af61yrhni' #declare my key 


def en_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8') #delcaring a function for encoding to base64

def en_aes(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext #delcaring function



def de_aes(key: bytes, ciphertext: bytes) -> bytes:
    ciph = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decry = ciph.decryptor()
    padded_data = decry.update(ciphertext) + decry.finalize()
    unpadd = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain = unpadd.update(padded_data) + unpadd.finalize()
    return plain #declare our decryption using aes 

def ser_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8') #serializing our key into pem

def deser_key(pem_bytes):
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None
    )
#deserialize the key

def get_valid_key():
    curr_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn1:
        cursor = conn1.execute(query, (curr_time,))
        key_data = cursor.fetchall()


    keys = [(data[0], deser_key(de_aes(NOT_MY_KEY, data[1]))) for data in key_data]
    return keys


def get_priv_key(expired=False):
    current_time = int(datetime.datetime.utcnow().timestamp())

    if expired:
        query = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn2:
        cursor = conn2.execute(query, (current_time,))
        key_data = cursor.fetchone()
    if key_data:
        exp_value = key_data[2]
        if not isinstance(exp_value, int):
            print(f"Unexpected 'exp' value type: {type(exp_value)} - Value: {exp_value}")

        return key_data[0], deser_key(de_aes(NOT_MY_KEY, key_data[1]))
    return None, None


def get_user_id(username):
    with sqlite3.connect('totally_not_my_privateKeys.db') as connGetID:
        cursor = connGetID.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

    if user_data:
        return user_data[0]
    return None



conn = sqlite3.connect('totally_not_my_privateKeys.db') 

conn.execute('CREATE TABLE IF NOT EXISTS keys('
             'kid INTEGER PRIMARY KEY AUTOINCREMENT, '
             'key BLOB NOT NULL, '
             'exp INTEGER NOT NULL)')   #create my db named keys, that has 3 objects stored within them
conn.execute('CREATE TABLE IF NOT EXISTS users('
             'id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'username TEXT NOT NULL UNIQUE, '
             'password_hash TEXT NOT NULL, '
             'email TEXT UNIQUE, '
             'date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, '
             'last_login TIMESTAMP)')

conn.execute('CREATE TABLE IF NOT EXISTS auth_logs('
             'id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'request_ip TEXT NOT NULL, '
             'request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, '
             'user_id INTEGER, '
             'FOREIGN KEY(user_id) REFERENCES users(id))')


conn.commit()

unexpir_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expir_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
unexpir_key_PEM = ser_pem(unexpir_key)
expir_key_PEM = ser_pem(expir_key) #create all my keys needed 

now = int(datetime.datetime.utcnow().timestamp()) #get now time


encrypted_unexpired_key = en_aes(NOT_MY_KEY, unexpir_key_PEM.encode('utf-8'))
encrypted_expired_key = en_aes(NOT_MY_KEY, expir_key_PEM.encode('utf-8'))

conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, int(now-36000)))
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, int(now-36000)))
conn.commit()

hostName = "localhost" 
serverPort = 8080

class RateLimiter:
    def __init__(self, max_requests, per_seconds):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.request_times = {}

    def allow_request(self, ip):
        current_time = time.time()
        if ip not in self.request_times:
            self.request_times[ip] = [current_time]
            return True
        else:
            self.request_times[ip] = [t for t in self.request_times[ip] if current_time - t < self.per_seconds]
            if len(self.request_times[ip]) < self.max_requests:
                self.request_times[ip].append(current_time)
                return True
            else:
                return False #defining our rate limiter class


rate_limiter = RateLimiter(max_requests=10, per_seconds=1) #declare rate limiter

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return #define put

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return #define patch

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return #define delete

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return #define head

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]

            if not rate_limiter.allow_request(client_ip):
                self.send_response(429, "Too Many Requests")
                self.end_headers()
                return #check our rate limiter
            
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes("Test response", "utf-8"))
                return 


        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            generated_password = str(uuid.uuid4()) #generate our passcode  
            ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
            hashed_password = ph.hash(generated_password)#hash passcode

            with sqlite3.connect('totally_not_my_privateKeys.db') as connRegister:
                connRegister.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                                     (user_data['username'], user_data['email'], hashed_password))
                connRegister.commit() #commit into to db

            # return password
            response_data = {"password": generated_password}
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

        else:
            self.send_response(405)
            self.end_headers()
            return #define post

    def do_GET(self): 
        if self.path == "/.well-known/jwks.json":  #validate path
            valid_keys_with_kid = get_all_private_keys()
            jwks = {"keys": []}
            #create list
            for kid, key in valid_keys_with_kid:
                private_numbers = key.private_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(private_numbers.public_numbers.n),
                    "e": int_to_base64(private_numbers.public_numbers.e)
                })
            #return our list
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return #define get 

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer) #create web server
    try:
        webServer.serve_forever()  #start server
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()  #close server