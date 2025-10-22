import argparse, socket, struct, threading, sys, os
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Framing helpers ----------
def send_with_len(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        buf += chunk
    return buf

def recv_with_len(sock: socket.socket) -> bytes:
    raw = recv_all(sock, 4)
    (length,) = struct.unpack("!I", raw)
    return recv_all(sock, length)

# ---------- Crypto helpers ----------
def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pub = priv.public_key()
    return priv, pub

def rsa_pub_bytes(pub):
    return pub.public_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)

def rsa_load_pub(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())

def rsa_sign(priv, data: bytes) -> bytes:
    return priv.sign(
        data,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify(pub, signature: bytes, data: bytes):
    pub.verify(
        signature,
        data,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def derive_aes_key(shared_secret: bytes, length: int = 32) -> bytes:
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=length, otherinfo=None, backend=default_backend())
    return ckdf.derive(shared_secret)

# ---------- Messaging loops ----------
def send_loop(sock: socket.socket, rsa_priv, aes_key, stop_event: threading.Event):
    aesgcm = AESGCM(aes_key)
    try:
        while not stop_event.is_set():
            try:
                msg = input()
            except EOFError:
                # Ctrl-D or input closed
                stop_event.set()
                break
            if msg is None:
                continue
            # encrypt
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, msg.encode(), associated_data=None)
            payload = nonce + ciphertext  # send nonce || ciphertext
            signature = rsa_sign(rsa_priv, payload)
            # send both length-prefixed
            send_with_len(sock, payload)
            send_with_len(sock, signature)
            if msg.strip().lower() == "quit":
                stop_event.set()
                break
    except Exception as e:
        print(f"[send_loop] error: {e}")
        stop_event.set()

def recv_loop(sock: socket.socket, rsa_pub, aes_key, stop_event: threading.Event):
    aesgcm = AESGCM(aes_key)
    try:
        while not stop_event.is_set():
            # receive payload and signature (both len-prefixed)
            payload = recv_with_len(sock)
            signature = recv_with_len(sock)
            # verify signature (will raise if invalid)
            try:
                rsa_verify(rsa_pub, signature, payload)
            except Exception as e:
                print("[!] Signature verification failed:", e)
                stop_event.set()
                break
            # split nonce and ciphertext
            if len(payload) < 12:
                print("[!] Received malformed payload")
                stop_event.set()
                break
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            except Exception as e:
                print("[!] Decryption failed:", e)
                stop_event.set()
                break
            text = plaintext.decode(errors="replace")
            print(f"\n[peer] {text}")
            if text.strip().lower() == "quit":
                stop_event.set()
                break
    except ConnectionError:
        print("[*] Connection closed by peer")
        stop_event.set()
    except Exception as e:
        print(f"[recv_loop] error: {e}")
        stop_event.set()

# ---------- Server and Client flows ----------
def run_server(bind_addr: str, port: int):
    # RSA keypair and DH parameters
    rsa_priv, rsa_pub = generate_rsa_keypair()
    dh_params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((bind_addr, port))
    sock.listen(1)
    print(f"[+] Listening on {bind_addr}:{port} ... (ctrl-c to stop)")
    conn, addr = sock.accept()
    print(f"[+] Connection from {addr}")

    try:
        # 1) Send server RSA pub
        send_with_len(conn, rsa_pub_bytes(rsa_pub))

        # 2) Send DH params p and g as bytes (length-prefixed)
        param_nums = dh_params.parameter_numbers()
        p = param_nums.p
        g = param_nums.g
        p_bytes = p.to_bytes((p.bit_length() + 7)//8, 'big')
        g_bytes = g.to_bytes((g.bit_length() + 7)//8, 'big')
        send_with_len(conn, p_bytes)
        send_with_len(conn, g_bytes)

        # 3) Send server DH public key (DER)
        srv_dh_priv = dh_params.generate_private_key()
        srv_dh_pub = srv_dh_priv.public_key()
        srv_dh_pub_bytes = srv_dh_pub.public_bytes(encoding=serialization.Encoding.DER,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        send_with_len(conn, srv_dh_pub_bytes)

        # 4) Receive client RSA public key (PEM) then client DH public (DER)
        client_pub_pem = recv_with_len(conn)
        client_rsa_pub = serialization.load_pem_public_key(client_pub_pem, backend=default_backend())
        client_dh_pub_bytes = recv_with_len(conn)
        client_dh_pub = serialization.load_der_public_key(client_dh_pub_bytes, backend=default_backend())

        # 5) compute shared secret and derive AES key
        shared_secret = srv_dh_priv.exchange(client_dh_pub)
        aes_key = derive_aes_key(shared_secret, length=32)
        print("[*] Shared AES-GCM key derived. Secure chat ready. Type messages (type 'quit' to exit).")

        # start messaging threads
        stop_event = threading.Event()
        t_recv = threading.Thread(target=recv_loop, args=(conn, client_rsa_pub, aes_key, stop_event), daemon=True)
        t_send = threading.Thread(target=send_loop, args=(conn, rsa_priv, aes_key, stop_event), daemon=True)
        t_recv.start()
        t_send.start()
        t_recv.join()
        t_send.join()
    finally:
        try:
            conn.close()
        except:
            pass
        sock.close()
        print("[*] Server stopped.")

def run_client(connect_addr: str, port: int):
    rsa_priv, rsa_pub = generate_rsa_keypair()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((connect_addr, port))
    try:
        # 1) receive server RSA pub, p, g, server DH pub
        server_pub_pem = recv_with_len(sock)
        server_rsa_pub = serialization.load_pem_public_key(server_pub_pem, backend=default_backend())

        p_bytes = recv_with_len(sock)
        g_bytes = recv_with_len(sock)
        p = int.from_bytes(p_bytes, 'big')
        g = int.from_bytes(g_bytes, 'big')

        srv_dh_pub_bytes = recv_with_len(sock)
        srv_dh_pub = serialization.load_der_public_key(srv_dh_pub_bytes, backend=default_backend())

        # 2) generate client DH keypair and send client RSA pub and client DH pub
        params = dh.DHParameterNumbers(p, g).parameters(default_backend())
        cli_dh_priv = params.generate_private_key()
        cli_dh_pub = cli_dh_priv.public_key()
        cli_dh_pub_bytes = cli_dh_pub.public_bytes(encoding=serialization.Encoding.DER,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # send client RSA pub first, then client DH pub
        send_with_len(sock, rsa_pub_bytes(rsa_pub))
        send_with_len(sock, cli_dh_pub_bytes)

        # compute shared secret and derive AES key
        shared_secret = cli_dh_priv.exchange(srv_dh_pub)
        aes_key = derive_aes_key(shared_secret, length=32)
        print("[*] Shared AES-GCM key derived. Secure chat ready. Type messages (type 'quit' to exit).")

        stop_event = threading.Event()
        t_recv = threading.Thread(target=recv_loop, args=(sock, server_rsa_pub, aes_key, stop_event), daemon=True)
        t_send = threading.Thread(target=send_loop, args=(sock, rsa_priv, aes_key, stop_event), daemon=True)
        t_recv.start()
        t_send.start()
        t_recv.join()
        t_send.join()
    finally:
        try:
            sock.close()
        except:
            pass
        print("[*] Client stopped.")

# ---------- Help menu ----------
def print_help_menu():
    help_text = """
p2p_chat.py - Help & Usage
--------------------------

Description
  Simple peer-to-peer encrypted chat using:
    - RSA (2048) for signatures (PSS + SHA-256)
    - Diffie-Hellman for key agreement (2048-bit)
    - ConcatKDF(SHA256) to derive AES-GCM key
    - AES-GCM (32-byte key, 12-byte nonce) for authenticated encryption
    - Length-prefixed framing to avoid partial recv issues

Quick examples
  Run the server (accept one connection):
    python p2p_chat.py --mode server --bind 0.0.0.0 --port 12345

  Connect as a client:
    python p2p_chat.py --mode client --connect 1.2.3.4 --port 12345

  Type messages and press Enter. Type 'quit' to end the session.

Handshake sequence
  Server -> send: server RSA pub (PEM)
  Server -> send: DH params p, g (len-prefixed)
  Server -> send: server DH pub (DER)
  Client -> send: client RSA pub (PEM)
  Client -> send: client DH pub (DER)
  Both -> derive shared_secret, run KDF -> AES key

Messaging format
  Each message:
    payload = nonce (12 bytes) || AES-GCM ciphertext
    signature = RSA-PSS signature over payload
  On wire:
    [4-byte len][payload] [4-byte len][signature]

Notes & recommendations
  - This script generates ephemeral RSA keys each run. For real use, add persistent keys and TOFU.
  - AES-GCM provides confidentiality and integrity; still verify peer identity out-of-band if possible.
  - The script handles one connection per run. Use the multi-connection shell I provided earlier if you need many peers.
  - Install required package:
      pip install cryptography

Flags
  --menu / --help-menu : show this help menu and exit
  --mode server|client : run in server or client mode
  --bind               : bind address for server (default 127.0.0.1)
  --connect            : connect address for client (default 127.0.0.1)
  --port               : port to bind/connect (default 12345)

"""
    print(help_text)

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Peer-to-peer encrypted chat")
    parser.add_argument('--mode', choices=['server', 'client'], required=False)
    parser.add_argument('--bind', default='127.0.0.1', help='bind address for server')
    parser.add_argument('--connect', default='127.0.0.1', help='connect address for client')
    parser.add_argument('--port', type=int, default=12345)
    parser.add_argument('--menu', '--help-menu', action='store_true', dest='menu', help='show interactive help menu and exit')
    args = parser.parse_args()

    # If user asked for help menu, print it and exit
    if args.menu:
        print_help_menu()
        return

    # If mode not provided, show short usage and menu hint
    if not args.mode:
        print("Mode (--mode) not specified. Use --menu to see usage and examples.")
        print("Example: python p2p_chat.py --mode server --port 12345")
        return

    if args.mode == 'server':
        run_server(args.bind, args.port)
    else:
        run_client(args.connect, args.port)

if __name__ == "__main__":
    main()

