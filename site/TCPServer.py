from __future__ import annotations
import socketserver
from logging import Logger

class TCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address: socketserver._AfInetAddress, logger: Logger, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandler, bind_and_activate)
        self.logger = logger
        
class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.data = self.rfile.readline().decode()
        self.server.logger.debug(f"Received from {self.client_address[0]}:{self.client_address[1]}: {self.data}")
        self.server.logger.info(f"Received: {self.data}")