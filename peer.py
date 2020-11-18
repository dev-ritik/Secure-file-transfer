import socket
import struct
import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate

from encrypt import Encrypt
from utils import debug


class Peer:
    """
    Represents the state of a connected peer and has utility functions
    """
    REQUEST_FILE = 'RQFL'
    RESPONSE_FILE = 'RSFL'
    SEND_CERT = 'SECE'
    CERT_RESPONSE_VALID = 'RSCV'
    CERT_RESPONSE_INVALID = 'RSCI'

    def __init__(self, port, client_sock=None):
        self.server_port = port
        self.server_host = 'localhost'
        self.my_id = 'ritik123'
        self.client_sock = client_sock
        self.peer_cert = None
        if not client_sock:
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect(('localhost', int(port)))

    def add_peer_cert(self, cert: str) -> bool:
        try:
            self.peer_cert = load_pem_x509_certificate(str.encode(cert), default_backend())
            Encrypt.verify_key_chain(self.peer_cert)
            return True
        except:
            traceback.print_exc()
            return False

    @staticmethod
    def __make_msg(msg_type, msg_data: bytearray):
        msg = struct.pack("!4sL%ds" % len(msg_data), msg_type.encode('ascii'), len(msg_data), msg_data)
        return msg

    def recv_data(self, file_recv=False, fname=None, alias=None):
        """
        recv_data() -> (msg_type, msg_data)
        Receive a message from a peer connection. Returns (None, None)
        if there was any error.
        """
        try:
            msg_type = self.client_sock.recv(4)
            if not msg_type:
                return None, None

            lenstr = self.client_sock.recv(4)
            msglen = int(struct.unpack("!L", lenstr)[0])
            msg = b""
            while len(msg) != msglen:
                data = self.client_sock.recv(min(2048, msglen - len(msg)))
                if not len(data):
                    print('Data is none')
                    break
                msg += data

            if len(msg) != msglen:
                return None, None

        except KeyboardInterrupt:
            raise
        except:
            traceback.print_exc()
            return None, None

        return msg_type.decode('ascii'), msg

    def send_data(self, msg_type, msg_data):
        """
        send_data( message type, message data ) -> boolean status
        Send a message through a peer connection. Returns True on success
        or False if there was an error.
        """
        if isinstance(msg_data, str):
            msg_data = msg_data.encode('ascii')
        try:
            msg = self.__make_msg(msg_type, msg_data)
            # self.sd.write(msg)
            self.client_sock.send(msg)
            # self.sd.flush()
        except KeyboardInterrupt:
            raise
        except:
            traceback.print_exc()
            return False
        return True

    def close(self):
        """
        close()
        Close the peer connection. The send and recv methods will not work
        after this call.
        """

        self.client_sock.close()
        self.client_sock = None

    def __debug(self, msg):
        debug(msg)
