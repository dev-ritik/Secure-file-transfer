import json
import os
import sys
import threading
import traceback
from time import sleep

import requests
from cryptography.hazmat.primitives import serialization

from connection import ConnectionHandler
from encrypt import Encrypt


class LoginHandler:
    """
    Handle client login with corporate's auth server.
    Login ensures authentication and signs public key for establishing identity.
    """
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
    # print(my_pub_key)
    signed_cert = LoginHandler(my_pub_key, name, password).attempt_login()
    if signed_cert == "":
        exit(1)

    encrypt.add_signed_cert(signed_cert=signed_cert)

    server_port = int(input("Enter port to listen on: "))
    server_host = 'localhost'
    server_conn = ConnectionHandler(server_port, encrypt)

    request = bool(input("Do you like to request a file? t/f? ") == 't')

    print(f"Listening for incoming connections on port {server_host}:{server_port}")
    t = threading.Thread(target=server_conn.socket_listener, args=[]).start()
    sleep(1)
    if request:
        peer_port = int(input("Enter peer's port: "))
        file_name = input("Enter the file name: ")
        print(f"Requesting for file {file_name} on {server_host}:{peer_port}")
        server_conn.request_encrypted_file(server_host, peer_port, file_name)
