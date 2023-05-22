import logging
from OpenSSL import crypto
import threading
from TCPServer import TCPServer
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, OAEP, MGF1
from cryptography.hazmat.primitives import hashes
import os
import base64


class Site:
    CHUNK_SIZE = 1024
    
    def __init__(self, id: str, root_ip: str, logger: logging.Logger):
        if not isinstance(id, str):
            raise TypeError
        if not isinstance(root_ip, str):
            raise TypeError
        if not isinstance(logger, logging.Logger):
            raise TypeError
        self.id = id
        self.root_ip = root_ip
        self.logger = logger
        self.generate_pair()
        self.load_root_cert()


    def start(self) -> None:
        self.logger.info("Starting server")
        server_thread = threading.Thread(target=self.start_tcp_server)
        server_thread.start()
        if self.id == "A":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.root_ip, 1024))
                s.sendall("B:[3]Ping".encode())
        elif self.id == "B":
            # Code for B only
            pass
        else:
            # Code for C only
            pass
        server_thread.join()


    def start_tcp_server(self) -> None:
        with TCPServer(("0.0.0.0", 1024), self) as server:
            server.serve_forever()

    def create_symmetric_key(self):
        self.symmetric_key = Fernet.generate_key()
        return self.symmetric_key

    def check_certificate(self, certificate) -> bool:
        store_ctx = crypto.X509StoreContext(self.store, certificate)
        try:
            store_ctx.verify_certificate()
            valid = True
        except crypto.X509StoreContextError:
            valid = False
        return valid
    
    @classmethod
    def encrypt(cls, key: crypto.PKey, data: bytes) -> bytes:
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        chunks = [data[i:i + cls.CHUNK_SIZE] for i in range(0, len(data), cls.CHUNK_SIZE)]
        encrypted_chunks = [key.to_cryptography_key().encrypt(chunk, padding) for chunk in chunks]
        return b"||".join(encrypted_chunks)
    
    @classmethod
    def decrypt(cls, key: crypto.PKey, data: bytes) -> bytes:
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        chunks = data.split(b"||")
        decrypted_chunks = [key.to_cryptography_key().decrypt(chunk, padding) for chunk in chunks]
        return b"".join(decrypted_chunks)

    def generate_pair(self) -> None:
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, 2048)
        pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair).decode()
        self.logger.info(f"Public key:\n{crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair).decode()}")
        self.key_pair = key_pair
        self.logger.info(f"Private key:\n{crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode()}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # We connect to the Certification Authority
                s.connect((self.root_ip, 1025))
                # We send our public key in order to let the CA generate and encrypt our certificate
                pub_key_encoded = base64.b64encode(pub_key.encode()).decode()
                s.sendall(f"{self.id}:[1]{pub_key_encoded}".encode())
                encoded_certificate = s.recv(4096)
                self.logger.debug(f"Encoded and encrypted certificate:\n{encoded_certificate}")
                encrypted_certificate_data = base64.b64decode(encoded_certificate)
                self.logger.debug(f"Encrypted certificate data: {encrypted_certificate_data}")
                # Decryption of the certificate
                certificate_data = self.__class__.decrypt(self.key_pair, encrypted_certificate_data)
                # Loading of the signed certificate
                self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_data)
                self.logger.info(f"Signed certificate:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate).decode()}")
            except Exception as e:
                self.logger.error(e)



    def load_root_cert(self):
        with open(f"sec/{self.id}/root.pem", "r") as root_cert_file:
            self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_file.read())
            self.logger.debug(f"Root certificate:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, self.root_cert).decode()}")
            self.store = crypto.X509Store()
            self.store.add_cert(self.root_cert)

    # def send_encrypted_socket(self, s: socket.socket, message, )