import os

from OpenSSL import crypto
from OpenSSL.crypto import X509Store, X509StoreContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class Encrypt:
    """
    Handle client keys and certificates. Encrypts and decrypts data.
    """
    PASSPHRASE = "harvey_specter"

    def __init__(self, key_dir):
        self.key_dir = key_dir
        self.private_key = None
        self.public_key = None

    @staticmethod
    def verify_key_chain(peer_cert):
        root_cert = Encrypt.get_root_cert()
        root_cert = crypto.X509.from_cryptography(root_cert)
        peer_cert = crypto.X509.from_cryptography(peer_cert)

        store = X509Store()
        store.add_cert(root_cert)
        store_ctx = X509StoreContext(store, peer_cert)
        store_ctx.verify_certificate()

    def get_my_pub_key(self):
        if self.public_key:
            return self.public_key
        self.get_private_key()
        self.public_key = self.private_key.public_key()
        return self.public_key

    def add_signed_cert(self, signed_cert):
        with open(self.key_dir + "/signed_cert.crt", "wb") as f:
            f.write(signed_cert.encode('utf-8'))

    def get_signed_cert(self):
        with open(self.key_dir + '/signed_cert.crt', "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def get_signed_cert_str(self):
        return str(self.get_signed_cert().public_bytes(serialization.Encoding.PEM), "utf-8")

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

    def get_private_key(self):
        if self.private_key:
            return self.private_key
        private_key_path = self.key_dir + '/id_rsa.pem'
        if os.path.isfile(private_key_path) and os.access(private_key_path, os.R_OK):
            with open(private_key_path, 'rb') as pem_in:
                self.private_key = serialization.load_pem_private_key(pem_in.read(), b"passphrase",
                                                                      backend=default_backend())
        else:
            self.private_key = self.create_private_key(private_key_path)
        return self.private_key

    @staticmethod
    def get_root_cert():
        with open('keys/auth/rootCA.crt', "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    @staticmethod
    def get_root_pub_key():
        return Encrypt.get_root_cert().public_key()
