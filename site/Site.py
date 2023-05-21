import logging
from OpenSSL import crypto
import threading
from TCPServer import TCPServer
import socket
from cryptography.fernet import Fernet
import os


class Site:
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
    
    def generate_pair(self) -> None:
        private_key = crypto.PKey()
        private_key.generate_key(crypto.TYPE_RSA, 2048)
        pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, private_key).decode()
        self.private_key = private_key
        self.logger.debug(f"Private key:\n{crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key).decode()}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.root_ip, 1025))
                s.sendall(f"{self.id}:[1]{pub_key}".encode())
                certificate = crypto.load_certificate(crypto.FILETYPE_PEM, s.recv(4096))
                self.certificate = certificate
                self.logger.info(f"Signed certificate:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)}")
            except Exception as e:
                self.logger.error(e)
            
        
        
    def load_root_cert(self):
        with open(f"sec/{self.id}/root.pem", "r") as root_cert_file:
            self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_file.read())
            self.logger.debug(f"Root certificate: {crypto.dump_certificate(crypto.FILETYPE_PEM, self.root_cert).decode()}")
            self.store = crypto.X509Store()
            self.store.add_cert(self.root_cert)
            