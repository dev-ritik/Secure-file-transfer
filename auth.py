#!/usr/bin/python3
import json
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from urllib import parse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.oid import NameOID

HOST = 'localhost'
PORT = 12565


class Encrypt:
    def __init__(self):
        self.MY_PRIVATE_KEY = None

    def get_my_private_key(self):
        if not self.MY_PRIVATE_KEY:
            with open('keys/auth/rootCA.key', 'rb') as pem_in:
                self.MY_PRIVATE_KEY = load_pem_private_key(pem_in.read(), None, default_backend())
        return self.MY_PRIVATE_KEY

    @staticmethod
    def is_registered(name, password) -> bool:
        ALLOWED = {
            "ritik": "must_not_be_revealed"
        }
        return True if ALLOWED.get(name) and ALLOWED[name] == password else False

    def sign_public_key(self, public_key):
        # print(public_key)
        to_sign_key = serialization.load_pem_public_key(public_key.encode('utf-8'), backend=default_backend())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Uttarakhand"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Roorkee"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IIT Roorkee"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Node 1"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject).issuer_name(issuer).public_key(
            to_sign_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(
            datetime.utcnow() + timedelta(days=10)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False, ).sign(self.get_my_private_key(), hashes.SHA256())

        return str(cert.public_bytes(serialization.Encoding.PEM), "utf-8")

    def get_signed_key(self, name, password, public_key) -> str:
        if not Encrypt.is_registered(name, password):
            return ""
        return self.sign_public_key(public_key)


class GetHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        parsed_path = parse.urlparse(self.path)
        if parsed_path.path == '/verify':
            data = self.rfile.read(int(self.headers['Content-Length']))
            data = json.loads(data.decode("utf-8"))
            # print(data)
            if not data.get('name') or not data.get('password') or not data.get('public_key'):
                self.send_error(400, "Bad Request {}".format(self.path))
                return
            self.send_response(200)
            self.send_header('Content-Type',
                             'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(
                Encrypt().get_signed_key(data['name'], data['password'], data['public_key']).encode('utf-8'))
        else:
            self.send_error(404, "Path not found {}".format(self.path))


if __name__ == '__main__':
    from http.server import HTTPServer

    server = HTTPServer((HOST, PORT), GetHandler)
    server.serve_forever()
