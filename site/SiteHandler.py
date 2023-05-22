import socketserver
import re
import socket
import base64

from OpenSSL import crypto

class SiteHandler(socketserver.StreamRequestHandler):
    CERTICATE_REQUEST = 1
    SYMMETRIC_KEY_REQUEST = 2
    SYMMETRIC_KEY_SEND = 4
    MESSAGE = 3
    
    def handle(self) -> None:
        self.data = self.rfile.readline().decode()
        self.server.logger.debug(f"Received from {self.client_address[0]}:{self.client_address[1]}: {self.data}")
        match = re.match(r"(?P<site_src>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data)
        if match is None:
            self.server.logger.warning(f"It did not match the format I expected")
            return
        site_src = match.group('site_src')
        code = match.group('code')
        message = match.group('message')
        if not code.isnumeric():
            self.server.logger.warning(f"The code is not an integer")
            return
        code = int(code)
        self.server.logger.info(f"Received from {site_src}:[{code}] {message}")
        if code == self.MESSAGE:
            decrypted_message = self.server.symmetric_decrypt(self.server.comms[site_src]['symmetric_key'], base64.b64decode(message)).decode()
            self.server.logger.info(f"Decrypted message from {site_src}: {decrypted_message}")
            
        elif code == self.SYMMETRIC_KEY_REQUEST:
            # Reception of a certificate 
            # After validation
            # Site sends the symetric key
            # try:
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, base64.b64decode(message))
            if self.server.check_certificate(certificate):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.server.root_ip, 1024))
                    if site_src not in self.server.comms.keys():
                        self.server.comms[site_src] = dict()
                    self.server.comms[site_src]['symmetric_key'] = self.server.create_symmetric_key()
                    self.server.logger.debug(f"Symm key: {self.server.__class__.encrypt(certificate.get_pubkey(), self.server.comms[site_src]['symmetric_key'])}")
                    encoded_sym_key = base64.b64encode(self.server.__class__.encrypt(certificate.get_pubkey(), self.server.comms[site_src]['symmetric_key']))
                    self.server.logger.debug(f"Symm key: {encoded_sym_key}")
                    s.sendall(f"{site_src}:[{self.SYMMETRIC_KEY_SEND}]{encoded_sym_key.decode()};{base64.b64encode(self.server.symmetric_encrypt(self.server.comms[site_src]['symmetric_key'], 'Ping'.encode())).decode()}".encode())
                    # s.sendall(f"{site_src}:[{self.MESSAGE}]{base64.b64encode(self.server.symmetric_encrypt(self.server.comms[site_src]['symmetric_key'], 'Ping'.encode())).decode()}".encode())
            else:
                self.server.logger.warning(f"Site {site_src} does not have a valid certificate.")
            # except Exception as e:
            #     self.server.logger.error(e)
        elif code == self.CERTICATE_REQUEST:
            # When site is asked to give its certificate
            # It will ask in return a symetric key
            # The key will be encrypted with the public key contained in the certificate
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # try:
                s.connect((self.server.root_ip, 1024))
                s.sendall(f"{site_src}:[{self.SYMMETRIC_KEY_REQUEST}]{base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, self.server.certificate)).decode()}".encode())
                # except Exception as e:
                #     self.server.logger.error(e)
        elif code == self.SYMMETRIC_KEY_SEND:
            if site_src not in self.server.comms.keys():
                self.server.comms[site_src] = dict()
            key, message = message.split(";")
            self.server.logger.debug(f"key: {key}")
            self.server.logger.debug(f"message: {message}")
            self.server.comms[site_src]['symmetric_key'] = self.server.__class__.decrypt(self.server.key_pair, base64.b64decode(key))
            self.server.logger.debug(f"key: {self.server.comms[site_src]['symmetric_key']}")
            decrypted_message = self.server.symmetric_decrypt(self.server.comms[site_src]['symmetric_key'], base64.b64decode(message)).decode()
            self.server.logger.info(f"Decrypted message from {site_src}: {decrypted_message}")
            if decrypted_message == "Ping":
                encrypted_message = base64.b64encode(self.server.symmetric_encrypt(self.server.comms[site_src]['symmetric_key'], "Pong".encode()))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.server.root_ip, 1024))
                    s.sendall(f"{site_src}:[{self.MESSAGE}]{encrypted_message.decode()}".encode())
        else:
            self.server.site.logger.warning(f"Unknwon code {code}")