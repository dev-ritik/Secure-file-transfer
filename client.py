import json
import os
import traceback

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class Encrypt:
    PASSPHRASE = "harvey_specter"

    def __init__(self, key_dir):
        self.key_dir = key_dir
        self.private_key = None
        self.public_key = None

    def get_root_cert(self, filepath):
        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
            with open(filepath, "rb") as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        else:
            return None

    def get_my_pub_key(self):
        if self.public_key:
            return self.public_key
        if self.private_key:
            return self.private_key.public_key()
        private_key_path = self.key_dir + '/id_rsa.pem'
        if os.path.isfile(private_key_path) and os.access(private_key_path, os.R_OK):
            with open(private_key_path, 'rb') as pem_in:
                self.private_key = serialization.load_pem_private_key(pem_in.read(), b"passphrase",
                                                                      backend=default_backend())
                self.public_key = self.private_key.public_key()
                return self.public_key
        else:
            self.private_key = self.create_private_key(private_key_path)
            self.public_key = self.private_key.public_key()
            return self.public_key

    def add_signed_cert(self, signed_cert):
        with open(self.key_dir + "/signed_cert.crt", "wb") as f:
            f.write(signed_cert.encode('utf-8'))

    @staticmethod
    def create_private_key(filename: str):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048)

        with open(filename, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"), ))

        return key


class LoginHandler:
    AUTH_SERVER_URL = 'http://localhost:12565'

    def __init__(self, pub_key: str, name="ritik", password="must_not_be_revealed"):
        self.name = name
        self.password = password
        self.pub_key = pub_key

    def attempt_login(self) -> str:
        if not self.name or not self.password:
            print("Enter name and password")
            return ""
        payload = {
            "name": self.name,
            "password": self.password,
            "public_key": self.pub_key,
        }
        try:
            resp = requests.post(LoginHandler.AUTH_SERVER_URL + '/verify', data=json.dumps(payload))
        except Exception as e:  # This is the correct syntax
            traceback.print_exc()
            print("Auth Server Connection Error")
            return ""
        print('Certificate Signed')
        return resp.text.strip()


class SendFileHandler:
    def __init__(self):
        pass


class RequestFileHandler:
    def __init__(self):
        pass


if __name__ == '__main__':
    name = 'ritik'
    password = "must_not_be_revealed"

    my_keys_dir = f'keys/client/{name}'
    if not os.path.exists(my_keys_dir):
        os.makedirs(my_keys_dir)

    encrypt = Encrypt(my_keys_dir)
    my_pub_key = str(
        encrypt.get_my_pub_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1), "utf-8")
    # print(my_pub_key)
    signedcert = LoginHandler(my_pub_key, name, password).attempt_login()
    # print(signedcert)
    encrypt.add_signed_cert(signed_cert=signedcert)
