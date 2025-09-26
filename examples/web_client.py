#!/usr/bin/env python3
import socket
import ssl
import sys
import re

# Default values
DEFAULT_CERT_FILE = './certificates/server.crt'
DEFAULT_KEY_FILE = './certificates/server.key'
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 4433

BUFFER_SIZE = 4096

def create_tls_context(certfile: str, keyfile: str, keylog_file: str = None) -> ssl.SSLContext:
    """
    Create and configure an SSL/TLS context for the server.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if keylog_file:
        context.keylog_filename = keylog_file  # Useful for Wireshark using TCP and not VSOCK
    return context

def receive_response(connstream: ssl.SSLSocket, buffer_size: int = BUFFER_SIZE) -> str:
    """
    Receive a response from the client.
    Returns the decoded response string, or None if the client closed the connection.
    """
    data = connstream.recv(buffer_size)
    if not data:
        return None
    return data.decode(errors='ignore')

def handle_server(connstream: ssl.SSLSocket, host: str) -> None:
    """
    Handle the interaction with a single TLS client.
    Send a GET request and print the response.
    """
    counter = 0
    while True:   
        
        if counter == 1:
            http_request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: PythonTLSClient/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "Content-Length: 1\r\n"
                "\r\n"
                "A"  # Body with a single character
            )
        else:
            http_request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: PythonTLSClient/1.0\r\n"
                "Accept: */*\r\n"
                "Content-Length: 1\r\n"
                "\r\n"
                "A"  # Body with a single character
            )
        
        print("[*] Sending GET request:")
        print(http_request)
        
        connstream.sendall(http_request.encode("utf-8"))

        response = b""
        while True:
            print("[*] Waiting for response...")
            data = connstream.recv(BUFFER_SIZE)
            if not data:
                break
            response += data
            header_end = response.find(b"\r\n\r\n")
            if header_end != -1:
                headers = response[:header_end].decode()
                body_start = header_end + 4
                content_length_match = re.search(r"Content-Length:\s*(\d+)", headers, re.IGNORECASE)
                if content_length_match:
                    length = int(content_length_match.group(1))
                    while len(response) - body_start < length:
                        response += connstream.recv(BUFFER_SIZE)
                    response[body_start:body_start+length]
                    break

        print("[*] Received response:")
        print(response.decode(errors="ignore"))
    
        counter += 1
        if counter == 2:
            print("[*] EXIT command sent, closing connection")
            connstream.unwrap()  # Perform TLS shutdown handshake
            break

def main():
    """
    TLS server that accepts a single client connection,
    sends commands to the client, and receives responses.
    """
    key_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_KEY_FILE
    cert_file = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CERT_FILE
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
    host = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_HOST
    
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"[*] TLS server listening on {host}:{port}")
    context = create_tls_context(certfile=cert_file, keyfile=key_file, keylog_file="tls_keylog.log")
    newsocket, fromaddr = bindsocket.accept()
    print(f"[*] Incoming TLS connection from {fromaddr}")
    connstream = context.wrap_socket(newsocket, server_side=True)

    try:
        handle_server(connstream, host)
    except ssl.SSLError as e:
        print("[!] SSL Error:", e)
    except Exception as e:
        print("[!] Error:", e)
    except KeyboardInterrupt:
        print("\n[*] Server interrupted by user")
    finally:
        connstream.close()
        bindsocket.close()
        print("[*] Connection closed")

if __name__ == "__main__":
    main()
