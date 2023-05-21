from __future__ import annotations
import socketserver
from logging import Logger
import re
import socket

class Router(socketserver.ThreadingTCPServer):
    """Class responsible of routing messages between sites

    Args:
        server_address (socketserver._AfInetAddress): IP address + Port
        logger (Logger): logger
        routing_table (dict): Routing table
        bind_and_activate (bool)
    """
    def __init__(self, server_address: socketserver._AfInetAddress, logger: Logger, routing_table: dict, bind_and_activate: bool = True) -> None:
        super().__init__(server_address, RouterHandler, bind_and_activate)
        self.logger = logger
        self.routing_table = routing_table
        
class RouterHandler(socketserver.StreamRequestHandler):
    """

    Args:
        request (socketserver._RequestType):
        client_address (socketserver._RetAddress):
        server (Router):
    """
    def __init__(self, request: socketserver._RequestType, client_address: socketserver._RetAddress, server: Router) -> None:
        if not isinstance(server, Router):
            raise TypeError("Expecting TCPServer")
        super().__init__(request, client_address, server)
       
    def handle(self) -> None:
        self.data = self.rfile.readline().strip().decode()
        self.server.logger.debug(f"Received from {self.client_address[0]}:{self.client_address[1]}: '{self.data}'")
        # Find the site source in the routing table
        site_src = next((site for site, ip_addres in self.server.routing_table.items() if ip_addres == self.client_address[0]), None)
        if site_src is None:
            self.server.logger.warning("Unknown source site.")
            return
        match = re.match(r"(?P<site_dest>[A-Z]):\[(?P<code>\d)\](?P<message>.*)", self.data)
        if match is None:
            self.server.logger.warning(f"It did not match the format I expected")
            return
        site_dest = match.group('site_dest')
        code = match.group('code')
        message = match.group('message')
        if site_dest not in self.server.routing_table.keys():
            self.server.logger.warning(f"Unknown destination site.")
            return
        self.server.logger.info(f"Routing message '{message}' from {site_src} to {site_dest}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((self.server.routing_table[site_dest], 1024))
                sock.sendall(f"{site_src}:[{code}]{message}".encode())
            except Exception as e:
                self.server.logger.error(e)