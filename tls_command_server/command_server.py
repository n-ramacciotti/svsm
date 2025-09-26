import socket
import ssl

# TLS certificate and private key paths
CERTFILE = './certificates/server.crt'
KEYFILE = './certificates/server.key'

# TCP/IP host and port
HOST = "127.0.0.1"     # Listen on localhost
PORT = 4433            # TLS server port

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

def handle_client(connstream: ssl.SSLSocket) -> None:
    """
    Handle the interaction with a single TLS client.
    """
    while True:
        cmd = input("Command to send to client A ('EXIT' to close) > ") 
        
        if cmd.lower() == "shutdown":
            connstream.unwrap()
            break    
        
        # Send command
        connstream.sendall(cmd.encode())

        # Receive and print the client's response
        response = receive_response(connstream)
        if response:
            print("[CLIENT A]:", response)
        else:
            print("[*] Client A closed the connection")
            break
        
        if cmd.lower() == "exit" :
            print("[*] EXIT command sent, closing connection")
            connstream.unwrap()  # Perform TLS shutdown handshake
            break

def main():
    """
    TLS server that accepts a single client connection,
    sends commands to the client, and receives responses.
    """
    # --- Socket creation ---
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)
    print(f"[*] TLS server listening on {HOST}:{PORT}")

    # --- SSL/TLS context ---
    context = create_tls_context(CERTFILE, KEYFILE, keylog_file="tls_keylog.log")

    # --- Accept client connection ---
    newsocket, fromaddr = bindsocket.accept()
    print(f"[*] Incoming TLS connection from {fromaddr}")

    # Wrap the socket with TLS
    connstream = context.wrap_socket(newsocket, server_side=True)

    try:
        handle_client(connstream)
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
