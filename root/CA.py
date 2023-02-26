import socketserver
from logging import Logger
import re
import datetime
import OpenSSL.crypto as crypto


class CA(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, logger: Logger, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, CAHandler, bind_and_activate)
        self.logger = logger
        with open("sec/certificate.crt", "r") as certificate_file:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_file)
        with open("sec/privateKey.key", "r") as private_key_file:
            self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file)
        
class CAHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.data = self.rfile.readline().decode()
        match = re.match(r"(?P<code>\d): (?P<message>.*)", self.data)
        if match is None:
            self.server.logger.warning("Message not formatted properly.")
            return
        code = int(match.group('code'))
        message = match.group('message')
        if code == 1:
            # Signature
            pass
        elif code == 2:
            # Vérification
            pass
        elif code == 3:
            # Echange de clé pub pour communiquer
            pass
        else:
            return
        