import socketserver
import re
import base64

from OpenSSL import crypto

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes

class CA(socketserver.ThreadingTCPServer):
    CHUNK_SIZE = 100
    
    def __init__(self, server_address, logger, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, CAHandler, bind_and_activate)
        self.logger = logger
        with open("sec/certificate.pem") as cert_file:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
        with open("sec/private_key.pem") as private_key_file:
            self.key_pair = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
        
    def signed_certificate(self, public_key: crypto.PKey, site: str) -> crypto.X509:
        certificate = crypto.X509()
        certificate.get_subject().CN = site
        certificate.set_serial_number(1)
        certificate.gmtime_adj_notBefore(0)
        certificate.gmtime_adj_notAfter(31536000) # Valid for a year
        certificate.set_issuer(self.certificate.get_subject())
        certificate.set_pubkey(public_key)
        certificate.sign(self.key_pair, 'sha256')
        return certificate
    
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
        
class CAHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.data = self.request.recv(4096).strip().decode()
        if self.data.strip() == "":
           return
        match = re.match(r"(?P<site_src>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data,)
        if match is None:
            self.server.logger.warning("Message not formatted properly.")
            return
        site_src = match.group('site_src')
        code = int(match.group('code'))
        message = match.group('message')
        message = base64.b64decode(message).decode()
        if code == 1:
            # Signature
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, message.encode())
            self.server.logger.debug(f"Public key for {site_src}:\n{crypto.dump_publickey(crypto.FILETYPE_PEM, public_key).decode()}")
            certificate = self.server.signed_certificate(public_key, site_src)
            self.server.logger.info(f"Certificate for {site_src}:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode()}")
            self.server.logger.debug(f"Length (1) {len(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))}")
            encrypted_certificate = self.server.__class__.encrypt(public_key, crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
            self.server.logger.debug(f"Length (2) {len(encrypted_certificate)}")
            self.server.logger.debug(f"Encrypted certificate for {site_src}:\n{encrypted_certificate}")
            encoded_certificate = base64.b64encode(encrypted_certificate)
            self.server.logger.debug(f"Encoded and encrypted certificate for {site_src}:\n{encoded_certificate}")
            # We encrypt the certificate, encode it in base64 and send it
            self.request.sendall(encoded_certificate)
        
         