# p2p_chat.py - Help & Usage







## Description

  Simple peer-to-peer encrypted chat using:
  
  ```
    - RSA (2048) for signatures (PSS + SHA-256)
    - Diffie-Hellman for key agreement (2048-bit)
    - ConcatKDF(SHA256) to derive AES-GCM key
    - AES-GCM (32-byte key, 12-byte nonce) for authenticated encryption
    - Length-prefixed framing to avoid partial recv issues
  ```
## Quick examples

  Run the server (accept one connection):
  
  ```
    python p2p_chat.py --mode server --bind 0.0.0.0 --port 12345
  ```
  Connect as a client:
  
  ```
    python p2p_chat.py --mode client --connect 1.2.3.4 --port 12345
  ```

  Type messages and press Enter. Type 'quit' to end the session.

## Handshake sequence

```
  Server -> send: server RSA pub (PEM)
  Server -> send: DH params p, g (len-prefixed)
  Server -> send: server DH pub (DER)
  Client -> send: client RSA pub (PEM)
  Client -> send: client DH pub (DER)
  Both -> derive shared_secret, run KDF -> AES key
```

## Messaging format

  Each message:
  ```
    payload = nonce (12 bytes) || AES-GCM ciphertext
    signature = RSA-PSS signature over payload
  ```
  On wire:
  
  ```
    [4-byte len][payload] [4-byte len][signature]
  ```
## Notes & recommendations

  - This script generates ephemeral RSA keys each run. For real use, add persistent keys and TOFU.
  - AES-GCM provides confidentiality and integrity; still verify peer identity out-of-band if possible.
  - The script handles one connection per run. Use the multi-connection shell I provided earlier if you need many peers.
  - Install required package:
    
```
      pip install cryptography
```
