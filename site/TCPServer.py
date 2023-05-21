from __future__ import annotations
import socketserver
import re

import socket

class TCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address: socketserver._AfInetAddress, site: Site, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RequestHandler, bind_and_activate)
        self.site = site
        
class RequestHandler(socketserver.StreamRequestHandler):
    CERTICATE_REQUEST = 1
    SYMETRIC_KEY = 2
    MESSAGE = 3
    
    def handle(self) -> None:
        self.data = self.rfile.readline().decode()
        self.server.site.logger.debug(f"Received from {self.client_address[0]}:{self.client_address[1]}: {self.data}")
        match = re.match(r"(?P<site_src>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data)
        if match is None:
            self.server.site.logger.warning(f"It did not match the format I expected")
            return
        site_src = match.group('site_src')
        code = match.group('code')
        message = match.group('message')
        if not code.isnumeric():
            self.server.site.logger.warning(f"The code is not an integer")
            return
        code = int(code)
        self.server.site.logger.info(f"Received from {site_src}:[{code}] {message}")
        if code == self.MESSAGE:
            if message == "Ping":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try:
                        s.connect((self.server.site.root_ip, 1024))
                        s.sendall(f"{site_src}:[{code}]Pong".encode())
                    except Exception as e:
                        self.server.site.logger.error(e)
        elif code == self.SYMETRIC_KEY:
            pass
        elif code == self.CERTICATE_REQUEST:
            pass
        else:
            self.server.site.logger.warning(f"Unknwon code {code}")