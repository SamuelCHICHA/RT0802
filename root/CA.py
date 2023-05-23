import socketserver
import re
import base64

from OpenSSL import crypto

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes

class CA(socketserver.ThreadingTCPServer):
    """
    Class meant to represent the certification authority.
    It responds to request asking for a signed certificate.
    It derives from the ThreadingTCPServer so it can listen for these requests.
    """
    
    # Size of the chunk for encryption
    CHUNK_SIZE = 100
    
    def __init__(self, server_address, logger, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, CAHandler, bind_and_activate)
        self.logger = logger
        # Loading certificate
        with open("sec/certificate.pem") as cert_file:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
        # Loading private key
        with open("sec/private_key.pem") as private_key_file:
            self.key_pair = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
    
    def signed_certificate(self, public_key: crypto.PKey, site: str) -> crypto.X509:
        """Method designed to generate a signed certificate from a public key.

        Args:
            public_key (crypto.PKey): Public key
            site (str): Site identifier

        Returns:
            crypto.X509: Generated certificate
        """
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
        """Encrypts data using a public key

        Args:
            key (crypto.PKey): public key used for encryption
            data (bytes): data to be encrypted

        Returns:
            bytes: data encrypted
        """
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        # Splitting data into chunks so it can encrypted
        # Otherwise data would be too big to be encrypted
        chunks = [data[i:i + cls.CHUNK_SIZE] for i in range(0, len(data), cls.CHUNK_SIZE)]
        encrypted_chunks = [key.to_cryptography_key().encrypt(chunk, padding) for chunk in chunks]
        return b"||".join(encrypted_chunks)
    
    @classmethod
    def decrypt(cls, key: crypto.PKey, data: bytes) -> bytes:
        """Decrypts data using a private key

        Args:
            key (crypto.PKey): private key used for decryption
            data (bytes): data to be decrypted

        Returns:
            bytes: data decrypted
        """
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        chunks = data.split(b"||")
        decrypted_chunks = [key.to_cryptography_key().decrypt(chunk, padding) for chunk in chunks]
        return b"".join(decrypted_chunks)
        
class CAHandler(socketserver.StreamRequestHandler):
    """Class meant to represent the handler associated to the threaded tcp server"""
    def handle(self) -> None:
        """Method meant to handle incomming data on the socket"""
        self.data = self.request.recv(4096).strip().decode()
        if self.data.strip() == "":
           return
        # We divide the data according to our format 
        match = re.match(r"(?P<site_src>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data,)
        if match is None:
            self.server.logger.warning("Message not formatted properly.")
            return
        site_src = match.group('site_src')
        code = int(match.group('code'))
        message = match.group('message')
        message = base64.b64decode(message).decode()
        if code == 1:
            # Signed certification request
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, message.encode())
            self.server.logger.debug(f"Public key for {site_src}:\n{crypto.dump_publickey(crypto.FILETYPE_PEM, public_key).decode()}")
            # Certificate generation
            certificate = self.server.signed_certificate(public_key, site_src)
            self.server.logger.info(f"Certificate for {site_src}:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode()}")
            self.server.logger.debug(f"Length (1) {len(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))}")
            # Encryption of the certificate
            encrypted_certificate = self.server.__class__.encrypt(public_key, crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
            self.server.logger.debug(f"Length (2) {len(encrypted_certificate)}")
            self.server.logger.debug(f"Encrypted certificate for {site_src}:\n{encrypted_certificate}")
            # Base64 Encoding
            encoded_certificate = base64.b64encode(encrypted_certificate)
            self.server.logger.debug(f"Encoded and encrypted certificate for {site_src}:\n{encoded_certificate}")
            # Sending
            self.request.sendall(encoded_certificate)
        
         