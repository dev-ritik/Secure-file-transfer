import json
import os
import socket
import struct
import sys
import threading
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


def debug(msg):
    """ Prints a message to the screen with the name of the current thread
    """

    print("[%s] %s" % (str(threading.currentThread().getName()), msg))


class Peer:
    REQUEST_FILE = 'RQFL'
    RESPONSE_FILE = 'RSFL'
    MSG_TYPES = {
        'REQUEST_FILE': REQUEST_FILE
    }

    def __init__(self, port, client_sock=None):
        self.serverport = port
        self.serverhost = 'localhost'
        self.myid = 'ritik123'
        self.client_sock = client_sock
        if not client_sock:
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect(('localhost', int(port)))

    @staticmethod
    def __make_msg(msg_type, msg_data: bytearray):
        msg = struct.pack("!4sL%ds" % len(msg_data), msg_type.encode('ascii'), len(msg_data), msg_data)
        return msg

    def recvdata(self, file_recv=False, fname=None, alias=None):
        """
        recvdata() -> (msgtype, msgdata)
        Receive a message from a peer connection. Returns (None, None)
        if there was any error.
        """
        try:
            msgtype = self.client_sock.recv(4)
            if not msgtype:
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

        return msgtype.decode('ascii'), msg

    def send_data(self, msgtype, msgdata):
        """
        send_data( message type, message data ) -> boolean status
        Send a message through a peer connection. Returns True on success
        or False if there was an error.
        """
        if isinstance(msgdata, str):
            msgdata = msgdata.encode('ascii')
        try:
            msg = self.__make_msg(msgtype, msgdata)
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


class ConnectionHandler:
    def __init__(self, serverport, serverhost='localhost', maxpeers=5):
        self.maxpeers = int(maxpeers)
        self.serverport = int(serverport)
        self.serverhost = serverhost

        # self.peerlock = threading.Lock()  # ensure proper access to
        # peers list (maybe better to use
        # threading.RLock (reentrant))
        self.shutdown = False  # used to stop the main loop

        self.handlers = {Peer.REQUEST_FILE: self.file_request_handler}

    def file_request_handler(self, conn, msg):
        print("Received", msg)
        conn.send_data(Peer.RESPONSE_FILE, "Nothing much!")

    @staticmethod
    def make_server_socket(port, backlog=5):
        """ Constructs and prepares a server socket listening on the given
        port.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
        s.listen(backlog)
        return s

    def socket_listener(self):
        s = ConnectionHandler.make_server_socket(self.serverport)
        s.settimeout(2)
        self.__debug('Server started: (%s:%d)'
                     % (self.serverhost, self.serverport))

        while not self.shutdown:
            try:
                # self.__debug('Listening for connections...')
                client_sock, clientaddr = s.accept()
                client_sock.settimeout(None)

                threading.Thread(target=self.__handle_peer, args=[client_sock]).start()
            except KeyboardInterrupt:
                print('KeyboardInterrupt: stopping mainloop')
                self.shutdown = True
                continue
            except:
                # traceback.print_exc()
                continue

        # end while loop
        self.__debug('Main loop exiting')

        s.close()

    def __handle_peer(self, client_sock):
        """
        handle_peer( new socket connection ) -> ()
        Dispatches messages from the socket connection
        """

        self.__debug('New child ' + str(threading.currentThread().getName()))
        self.__debug('Connected ' + str(client_sock.getpeername()))

        host, port = client_sock.getpeername()
        conn = Peer(port, client_sock)
        try:
            msgtype, msgdata = conn.recvdata()
            if msgtype:
                msgtype = msgtype.upper()
            if msgtype not in self.handlers:
                self.__debug('Not handled: %s: %s' % (msgtype, msgdata))
            else:
                self.__debug('Handling peer msg: %s: %s' % (msgtype, msgdata))
                self.handlers[msgtype](conn, msgdata)
        except KeyboardInterrupt:
            raise
        except:
            if self.debug:
                traceback.print_exc()

        self.__debug('Disconnecting ' + str(client_sock.getpeername()))
        conn.close()

    def connect_and_request(self, host, port, msg_type, msgdata, waitreply=True):
        """
        connect_and_send( host, port, message type, message data,
        wait for a reply ) -> [ ( reply type, reply data ), ... ]
        Connects and sends a message to the specified host:port. The host's
        reply, if expected, will be returned as a list of tuples.
        """
        file_recv = False
        if msg_type == Peer.REQUEST_FILE:
            file_recv = True
        msgreply = []
        try:
            conn = Peer(port)
            conn.send_data(msg_type, msgdata)
            debug('Sent %s' % msg_type)

            if waitreply:
                one_reply = conn.recvdata(file_recv, msgdata)
                while one_reply != (None, None):
                    msgreply.append(one_reply)
                    debug('Got reply %s' % (str(msgreply)))
                    one_reply = conn.recvdata(file_recv, msgdata)
            conn.close()
        except KeyboardInterrupt:
            raise
        except:
            traceback.print_exc()

        return msgreply

    def __debug(self, msg):
        debug(msg)


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
    # signedcert = LoginHandler(my_pub_key, name, password).attempt_login()
    # print(signedcert)
    # encrypt.add_signed_cert(signed_cert=signedcert)

    server_port = sys.argv[1]
    server_host = 'localhost'
    server_conn = ConnectionHandler(server_port)

    t = threading.Thread(target=server_conn.socket_listener, args=[]).start()

    if int(sys.argv[2]) == 12666:
        print(server_conn.connect_and_request(server_host, sys.argv[2], Peer.REQUEST_FILE, "Hi! wanna hangout?!",
                                              waitreply=True))
