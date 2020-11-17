import socket
import threading
import traceback

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from peer import Peer
from utils import debug


class ConnectionHandler:
    def __init__(self, server_port, server_host='localhost', max_peers=5):
        self.max_peers = int(max_peers)
        self.server_port = int(server_port)
        self.server_host = server_host

        # self.peer_lock = threading.Lock()  # ensure proper access to
        # peers list (maybe better to use
        # threading.RLock (reentrant))
        self.shutdown = False  # used to stop the main loop

        self.handlers = {Peer.REQUEST_FILE: self.file_request_handler, Peer.SEND_CERT: self.record_cert_handler}

    def file_request_handler(self, conn: Peer, msg) -> bool:
        print("Received", msg)
        message = b"I like this!"
        if conn.peer_cert:
            public_key = conn.peer_cert.public_key()
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            # print(ciphertext)
            conn.send_data(Peer.RESPONSE_FILE, ciphertext)
        else:
            conn.send_data(Peer.RESPONSE_FILE, "I like this!")
        return True

    def record_cert_handler(self, conn: Peer, msg) -> bool:
        if conn.add_peer_cert(msg.decode("utf-8")):
            conn.send_data(Peer.CERT_RESPONSE_VALID, "")
            return False
        else:
            conn.send_data(Peer.CERT_RESPONSE_INVALID, "")
            return True

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
        s = ConnectionHandler.make_server_socket(self.server_port)
        s.settimeout(2)
        self.__debug('Server started: (%s:%d)'
                     % (self.server_host, self.server_port))

        while not self.shutdown:
            try:
                # self.__debug('Listening for connections...')
                client_sock, client_addr = s.accept()
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
        while True:
            try:
                msg_type, msg_data = conn.recv_data()
                if msg_type:
                    msg_type = msg_type.upper()
                if msg_type not in self.handlers:
                    self.__debug('Not handled: %s: %s' % (msg_type, msg_data))
                    break
                else:
                    self.__debug('Handling peer msg: %s: %s' % (msg_type, msg_data))
                    disconnect = self.handlers[msg_type](conn, msg_data)
                    if disconnect:
                        break
            except KeyboardInterrupt:
                raise
            except:
                traceback.print_exc()

        self.__debug('Disconnecting ' + str(client_sock.getpeername()))
        conn.close()

    # def connect_and_request(self, host, port, msg_type, msg_data, wait_reply=True):
    #     """
    #     connect_and_send( host, port, message type, message data,
    #     wait for a reply ) -> [ ( reply type, reply data ), ... ]
    #     Connects and sends a message to the specified host:port. The host's
    #     reply, if expected, will be returned as a list of tuples.
    #     """
    #     file_recv = False
    #     if msg_type == Peer.REQUEST_FILE:
    #         file_recv = True
    #     msg_reply = []
    #     try:
    #         conn = Peer(port)
    #         conn.send_data(msg_type, msg_data)
    #         debug('Sent %s' % msg_type)
    #
    #         if wait_reply:
    #             one_reply = conn.recv_data(file_recv, msg_data)
    #             while one_reply != (None, None):
    #                 msg_reply.append(one_reply)
    #                 debug('Got reply %s' % (str(msg_reply)))
    #                 one_reply = conn.recv_data(file_recv, msg_data)
    #         conn.close()
    #     except KeyboardInterrupt:
    #         raise
    #     except:
    #         traceback.print_exc()
    #
    #     return msg_reply

    def request_encrypted_file(self, host, port, my_cert: str, my_private_key):
        try:
            conn = Peer(port)
            conn.send_data(Peer.SEND_CERT, my_cert)
            debug('Sent %s' % Peer.SEND_CERT)

            msg_reply = conn.recv_data()
            debug('Got reply %s' % (str(msg_reply)))
            if msg_reply[0] != Peer.CERT_RESPONSE_VALID:
                print('ERROR')
                return

            conn.send_data(Peer.REQUEST_FILE, "I'm Donna.")
            debug('Sent %s' % Peer.REQUEST_FILE)
            msg_reply = conn.recv_data()
            debug('Got reply %s' % (str(msg_reply)))
            plaintext = my_private_key.decrypt(
                msg_reply[1],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            print(plaintext)
            conn.close()
        except KeyboardInterrupt:
            raise
        except:
            traceback.print_exc()

    def __debug(self, msg):
        debug(msg)
