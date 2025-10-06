#!/usr/bin/env python3
import http.server
import ssl
from pathlib import Path
import sys

# Default values
DEFAULT_KEY_FILE = 'certificates/server.key'
DEFAULT_CERT_FILE = 'certificates/server.crt'
DEFAULT_PORT = 4433
DEFAULT_HOST = 'localhost'
PAGE_CONTENT = b"Hello, HTTPS world!\n"

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        response = b"HTTP/1.1 200 OK\r\n" \
           b"Content-Type: text/plain\r\n" \
           b"Content-Length: " + str(len(PAGE_CONTENT)).encode() + b"\r\n" \
           b"\r\n" + PAGE_CONTENT
        self.wfile.write(response)
        self.connection.unwrap()

def run_server(key_file=DEFAULT_KEY_FILE, cert_file=DEFAULT_CERT_FILE, port=DEFAULT_PORT):
    httpd = http.server.HTTPServer((DEFAULT_HOST, port), MyHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving HTTPS on {DEFAULT_HOST}:{port} (cert: {cert_file}, key: {key_file})")
    httpd.serve_forever()

if __name__ == "__main__":
    key_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_KEY_FILE
    cert_file = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CERT_FILE
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
    host = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_HOST
    
    if not Path(key_file).is_file():
        print(f"Key file '{key_file}' not found!")
        sys.exit(1)
    if not Path(cert_file).is_file():
        print(f"Certificate file '{cert_file}' not found!")
        sys.exit(1)

    try:
        run_server(key_file, cert_file, port)
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"Error occurred: {e}")