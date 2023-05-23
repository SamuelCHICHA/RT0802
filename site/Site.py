from __future__ import annotations

import socket
import base64
import logging
import socketserver

from SiteHandler import SiteHandler

from OpenSSL import crypto

from os import urandom
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Site(socketserver.ThreadingTCPServer):
    CHUNK_SIZE = 100
    
    def __init__(self, server_address: socketserver._AfInetAddress, id: str, root_ip: str, logger: logging.Logger, bind_and_activate: bool = True):
        if not isinstance(id, str):
            raise TypeError
        if not isinstance(root_ip, str):
            raise TypeError
        if not isinstance(logger, logging.Logger):
            raise TypeError
        super().__init__(server_address, SiteHandler, bind_and_activate)
        self.id = id
        self.root_ip = root_ip
        self.logger = logger
        self.generate_pair()
        self.load_root_cert()
        self.comms = dict()

    @classmethod
    def create_symmetric_key(cls) -> bytes:
        """Generates a key of 128bit (8*16)

        Returns:
            bytes: key
        """
        return urandom(16)
    
    @classmethod
    def symmetric_encrypt(cls, key: bytes, data: bytes) -> bytes:
        """Encrypts data using AES

        Args:
            key (bytes): key
            data (bytes): data to be encrypted

        Returns:
            bytes: encrypted data
        """
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + encrypted
    
    @classmethod
    def symmetric_decrypt(cls, key: bytes, data: bytes) -> bytes:
        """Decrypts data using AES

        Args:
            key (bytes): key
            data (bytes): data

        Returns:
            bytes: decrypted data
        """
        iv = data[:16]
        encrypted = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        unpadder = PKCS7(128).unpadder()
        
        return unpadder.update(decrypted) + unpadder.finalize()

    def check_certificate(self, certificate: crypto.X509) -> bool:
        """Check if the certificate is valid according to the store

        Args:
            certificate (crypto.X509): certificate

        Returns:
            bool: is valid
        """
        store_ctx = crypto.X509StoreContext(self.store, certificate)
        try:
            store_ctx.verify_certificate()
            valid = True
        except crypto.X509StoreContextError as e:
            valid = False
        return valid
    
    @classmethod
    def encrypt(cls, key: crypto.PKey, data: bytes) -> bytes:
        """Asymetric encryption

        Args:
            key (crypto.PKey): public key
            data (bytes): data to be encrypted

        Returns:
            bytes: encrypted data
        """
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        # Splitting data into chunks so it can be encrypted
        chunks = [data[i:i + cls.CHUNK_SIZE] for i in range(0, len(data), cls.CHUNK_SIZE)]
        encrypted_chunks = [key.to_cryptography_key().encrypt(chunk, padding) for chunk in chunks]
        return b"||".join(encrypted_chunks)
    
    @classmethod
    def decrypt(cls, key: crypto.PKey, data: bytes) -> bytes:
        """Asymetric decryption

        Args:
            key (crypto.PKey): private key
            data (bytes): data to be decrypted

        Returns:
            bytes: decrypted data
        """
        padding = OAEP(MGF1(hashes.SHA256()), hashes.SHA256(), None)
        chunks = data.split(b"||")
        decrypted_chunks = [key.to_cryptography_key().decrypt(chunk, padding) for chunk in chunks]
        return b"".join(decrypted_chunks)
    

    def generate_pair(self) -> None:
        """Generate a pair of RSA key and get the certificate signed by the PKI"""
        # Key pair generation
        self.key_pair = crypto.PKey()
        self.key_pair.generate_key(crypto.TYPE_RSA, 2048)
        pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, self.key_pair).decode()
        self.logger.info(f"Public key:\n{crypto.dump_publickey(crypto.FILETYPE_PEM, self.key_pair).decode()}")
        self.logger.info(f"Private key:\n{crypto.dump_privatekey(crypto.FILETYPE_PEM, self.key_pair).decode()}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # We connect to the Certification Authority
                s.connect((self.root_ip, 1025))
                # We send our public key in order to let the CA generate and encrypt our certificate
                pub_key_encoded = base64.b64encode(pub_key.encode()).decode()
                s.sendall(f"{self.id}:[1]{pub_key_encoded}".encode())
                # We get the certificate
                encoded_certificate = s.recv(4096)
                self.logger.debug(f"Encoded and encrypted certificate:\n{encoded_certificate}")
                # Decoding certificate
                encrypted_certificate_data = base64.b64decode(encoded_certificate)
                self.logger.debug(f"Encrypted certificate data:\n{encrypted_certificate_data}")
                # Decrypting certificate
                certificate_data = self.__class__.decrypt(self.key_pair, encrypted_certificate_data)
                # Loading of the signed certificate
                self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_data)
                self.logger.info(f"Signed certificate:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate).decode()}")
        except Exception as e:
            self.logger.error(e)



    def load_root_cert(self):
        """Load the PKI certificate and add it to the store"""
        with open(f"sec/{self.id}/root.pem", "r") as root_cert_file:
            self.root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_file.read())
            self.logger.debug(f"Root certificate:\n{crypto.dump_certificate(crypto.FILETYPE_PEM, self.root_cert).decode()}")
            self.store = crypto.X509Store()
            self.store.add_cert(self.root_cert)
            
if __name__ == "__main__":
    # Checking that encryption works
    key = Site.create_symmetric_key()
    encrypted = Site.symmetric_encrypt(key, b"coucou")
    print(Site.symmetric_decrypt(key, encrypted))
