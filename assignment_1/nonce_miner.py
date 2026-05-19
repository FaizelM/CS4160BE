import hashlib
import struct


email = "F.Mangroe@student.tudelft.nl"
github_url = "https://github.com/FaizelM/CS4160BE.git"
prefix = (email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n")

def valid(hash_bytes: bytes) -> bool:
    return hash_bytes[0] == 0 and hash_bytes[1] == 0 and hash_bytes[2] == 0 and hash_bytes[3] < 16

def mine_for_nonce():
    nonce = 0

    while True:
        nonce_bytes = struct.pack(">Q", nonce)
        digest = hashlib.sha256(prefix + nonce_bytes).digest()
        if valid(digest):
            print("Solution found")
            print(f"Nonce: {nonce}")
            print(f"Hash: {digest.hex()}")
            break
        if nonce % 100 == 0:
            print("iteration: ", nonce)
        nonce += 1

def verify(email: str, github_url: str, nonce: int) -> bool:
    payload = (email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n" + struct.pack(">Q", nonce))
    digest = hashlib.sha256(payload).digest()
    return digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16

if __name__ == "__main__":
    email = "F.Mangroe@student.tudelft.nl"
    github_url = "https://github.com/FaizelM/CS4160BE.git"
    nonce = 385594074
    ok = verify(email, github_url, nonce)
    print("valid: " if ok else "invalid: ", ok)
    