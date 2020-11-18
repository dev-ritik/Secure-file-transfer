#!/usr/bin/python3
import base64
import json
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from urllib import parse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.oid import NameOID

HOST = 'localhost'
PORT = 12565

ALLOWED = {
    "user_alias": "password_which_must_not_be_revealed",
    "user1": "password1",
    "user2": "password2"
}


class Encrypt:
    """
    Handle client keys and certificates. Encrypts and decrypts data.
    """

    def __init__(self):
        self.MY_PRIVATE_KEY = None

    def get_my_private_key(self):
        if not self.MY_PRIVATE_KEY:
            with open('keys/auth/rootCA.key', 'rb') as pem_in:
                self.MY_PRIVATE_KEY = load_pem_private_key(pem_in.read(), None, default_backend())
        return self.MY_PRIVATE_KEY

    @staticmethod
    def is_registered(name, password) -> bool:
        global ALLOWED
        return True if ALLOWED.get(name) and ALLOWED[name] == password else False

    def generate_self_signed_cert(self):
        # Use openssl req -x509 -new -extensions v3_ca -nodes -key keys/auth/rootCA.key -sha256 -days 1024 -out
        # keys/auth/rootCA.crt
        # openssl verify --CAfile keys/auth/rootCA.crt keys/client/harvey/signed_cert.crt

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Uttarakhand"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Roorkee"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IIT Roorkee"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"MDG"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject).issuer_name(
            issuer).public_key(
            self.get_my_private_key().public_key()).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=10)
        ).sign(self.get_my_private_key(), hashes.SHA256())

        with open("keys/auth/rootCA.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def sign_public_key(self, name, public_key):
        # print(public_key)
        to_sign_key = serialization.load_pem_public_key(public_key.encode('utf-8'), backend=default_backend())

        with open('keys/auth/rootCA.crt', "rb") as f:
            root_crt = x509.load_pem_x509_certificate(f.read(), default_backend())
        issuer = root_crt.issuer
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"USA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"New York"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SLWW"),
            x509.NameAttribute(NameOID.COMMON_NAME, name)
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject).issuer_name(issuer).public_key(
            to_sign_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=10)).sign(self.get_my_private_key(), hashes.SHA256())

        return str(cert.public_bytes(serialization.Encoding.PEM), "utf-8")

    def get_signed_key(self, name, password, public_key) -> str:
        if not Encrypt.is_registered(name, password):
            return ""
        return self.sign_public_key(name, public_key)


class GetHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        parsed_path = parse.urlparse(self.path)
        if parsed_path.path == '/verify':
            data = self.rfile.read(int(self.headers['Content-Length']))
            data = json.loads(data.decode("utf-8"))
            plain_data = Encrypt().get_my_private_key().decrypt(
                base64.b64decode(data["payload"].encode('utf-8')),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            user_details = json.loads(plain_data.decode('utf8'))

            if not user_details.get('name') or not user_details.get('password') or not data.get('public_key'):
                self.send_error(400, "Bad Request {}".format(self.path))
                return
            cert = Encrypt().get_signed_key(user_details['name'], user_details['password'], data['public_key'])
            if cert == "":
                self.send_error(401, "Unauthorized {}".format(self.path))
            else:
                self.send_response(200)
                self.send_header('Content-Type',
                                 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(cert.encode('utf-8'))
        else:
            self.send_error(404, "Path not found {}".format(self.path))


def update_ALLOWED():
    print("Before starting authserver, you can add new users here...")
    while 1:
        try:
            request = str(input("Add new user? (t/f) "))

            if request == 't':
                _alias = str(input("Enter Alias: "))
                _password = str(input("Enter Password: "))
                ALLOWED[_alias] = _password
            else:
                break
        except Exception as e:
            print("Unexpected Exception:", str(e))
            break


if __name__ == '__main__':
    from http.server import HTTPServer

    update_ALLOWED()

    # Encrypt().generate_self_signed_cert()
    server = HTTPServer((HOST, PORT), GetHandler)

    print("Auth server running.")
    server.serve_forever()
