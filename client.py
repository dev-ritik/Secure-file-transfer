import base64
import json
import os
import threading
import traceback
from time import sleep

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from connection import ConnectionHandler
from encrypt import Encrypt


class LoginHandler:
    """
    Handle client login with corporate's auth server.
    Login ensures authentication and signs public key for establishing identity.
    """
    AUTH_SERVER_URL = 'http://localhost:12565'

    def __init__(self, name: str, password: str, pub_key: str):
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
        }
        ciphertext = Encrypt.get_root_pub_key().encrypt(
            json.dumps(payload).encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        data = {
            "payload": base64.b64encode(ciphertext).decode('utf-8'),
            "public_key": self.pub_key,
        }
        try:
            resp = requests.post(LoginHandler.AUTH_SERVER_URL + '/verify', data=json.dumps(data))
        except Exception:  # This is the correct syntax
            traceback.print_exc()
            print("Auth Server Connection Error")
            return ""

        if resp.status_code != 200:
            print("Unauthorized")
            return ""
        return resp.text.strip()


if __name__ == '__main__':
    name = input("Please enter your corp alias: ").strip()
    password = input("Please enter your password: ").strip()

    my_keys_dir = f'keys/client/{name}'
    if not os.path.exists(my_keys_dir):
        os.makedirs(my_keys_dir)

    encrypt = Encrypt(my_keys_dir)
    my_pub_key = str(
        encrypt.get_my_pub_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1), "utf-8")

    signed_cert = LoginHandler(name, password, my_pub_key).attempt_login()
    if signed_cert == "":
        exit(1)

    encrypt.add_signed_cert(signed_cert=signed_cert)

    server_port = int(input("Enter port to listen on: "))
    server_host = 'localhost'
    server_conn = ConnectionHandler(server_port, encrypt)

    t = threading.Thread(target=server_conn.socket_listener, args=[]).start()
    print(f"Listening for incoming connections on port {server_host}:{server_port}")
    sleep(1)

    while 1:
        try:
            request = bool(input("Do you like to request a file? t/f? ") == 't')

            if request:
                peer_port = int(input("Enter peer's port: "))
                file_name = input("Enter the file name: ")
                print(f"Requesting for file {file_name} on {server_host}:{peer_port}")
                server_conn.request_encrypted_file(server_host, peer_port, file_name)
            else:
                print("Enter t when you want to request a file, the program will wait till then...")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("Unexpected Exception:", str(e))
            break
    print("Exiting Program!")
    exit(1)
