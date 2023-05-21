import socketserver
from logging import Logger
import re
import OpenSSL.crypto as crypto


class CA(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, logger: Logger, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, CAHandler, bind_and_activate)
        self.logger = logger
        with open("sec/certificate.pem") as cert_file:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
        with open("sec/private_key.pem") as private_key_file:
            self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
    
        
    def signed_certificate(self, public_key: crypto.PKey, site: str) -> crypto.X509:
        certificate = crypto.X509()
        certificate.get_subject().CN = site
        certificate.set_serial_number(1)
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(31536000) # Valid for a year
        certificate.set_issuer(certificate.get_subject())
        certificate.set_pubkey(public_key)
        certificate.sign(self.private_key, 'sha256')
        return certificate
        
class CAHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.data = self.rfile.read().decode()
        if self.data.strip() == "":
           return 
        self.server.logger.debug(self.data)
        match = re.match(r"(?P<site_src>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data)
        if match is None:
            self.server.logger.warning("Message not formatted properly.")
            return
        site_src = match.group('site_src')
        code = int(match.group('code'))
        message = match.group('message')
        if code == 1:
            # Signature
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, message)
            certificate = self.server.signed_certificate(public_key, site_src)
            self.server.logger.debug(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode())
            self.request.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
        
         