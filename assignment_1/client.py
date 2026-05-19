import asyncio
import hashlib
import logging
import struct
from pathlib import Path
 
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.peer import Peer
from ipv8_service import IPv8
 
class _UnsupportedCurveFilter(logging.Filter):
    """Suppress the stream of 'Curve X is not supported' errors from old peers."""
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return "Curve" not in msg and "is not supported" not in msg
 
logging.getLogger("Lab1Community").addFilter(_UnsupportedCurveFilter())
logging.basicConfig(level=logging.DEBUG)
 
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
COMMUNITY_ID_HEX = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
KEY_FILE = "mykey.pem"
EMAIL = "F.Mangroe@student.tudelft.nl"
GITHUB_URL = "https://github.com/FaizelM/CS4160BE.git"
PREFIX = (EMAIL.encode("utf-8") + b"\n" + GITHUB_URL.encode("utf-8") + b"\n")

def valid(hash_bytes: bytes) -> bool:
    return hash_bytes[0] == 0 and hash_bytes[1] == 0 and hash_bytes[2] == 0 and hash_bytes[3] < 16

def mine_for_nonce() -> int:
    nonce = 0

    while True:
        nonce_bytes = struct.pack(">Q", nonce)
        digest = hashlib.sha256(PREFIX + nonce_bytes).digest()
        if valid(digest):
            print("Solution found")
            print(f"Nonce: {nonce}")
            print(f"Hash: {digest.hex()}")
            break
        if nonce % 100 == 0:
            print("iteration: ", nonce)
        nonce += 1
    return nonce

def verify(email: str, github_url: str, nonce: int) -> bool:
    payload = (email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n" + struct.pack(">Q", nonce))
    digest = hashlib.sha256(payload).digest()
    return digest[0] == 0 and digest[1] == 0 and digest[2] == 0 and digest[3] < 16
 
# ============================================================
# PAYLOADS
# ============================================================
 
class SubmissionPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenHutf8", "q"]
    names = ["email", "github_url", "nonce"]
 
 
class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]

class Lab1Community(Community):
    community_id = bytes.fromhex(COMMUNITY_ID_HEX)
 
    def __init__(self, settings):
        super().__init__(settings)
        self.server_peer = None
        self.submitted = False
        self.add_message_handler(ResponsePayload, self.on_response)
        self.register_task("status", self._log_status, interval=10.0, delay=10.0)
 
    def _log_status(self):
        peers = self.get_peers()
        print(f"[status] {len(peers)} peer(s) in community, server_peer={self.server_peer is not None}")
 
        if self.submitted or self.server_peer is not None:
            return
 
        for peer in peers:
            try:
                if peer.public_key.key_to_bin() == bytes.fromhex(SERVER_PUBLIC_KEY_HEX):
                    print("Server peer found!")
                    self.server_peer = peer
                    asyncio.ensure_future(self.submit())
                    return
            except Exception:
                continue
 
    def peer_added(self, peer: Peer) -> None:
        print(f"peer_added() called for: {peer}")
        try:
            key = peer.public_key.key_to_bin()
        except Exception as e:
            print(f"  Could not read key: {e}")
            return
 
        print(f"  Key: {key.hex()[:20]}...")
        if key == bytes.fromhex(SERVER_PUBLIC_KEY_HEX):
            print("  -> Server peer discovered!")
            self.server_peer = peer
            asyncio.ensure_future(self.submit())
        else:
            print(f"  -> Non-server peer, skipping.")
 
    def peer_removed(self, peer: Peer) -> None:
        try:
            key = peer.public_key.key_to_bin()
        except Exception:
            return
 
        if key == bytes.fromhex(SERVER_PUBLIC_KEY_HEX):
            print("WARNING: Server peer disconnected.")
            self.server_peer = None
 
    async def submit(self):
        if self.submitted:
            return
        self.submitted = True
 
        nonce = mine_for_nonce()
 
        assert verify(EMAIL, GITHUB_URL, nonce), "BUG: mined nonce does not satisfy difficulty!"
        print(f"\nPoW verified locally. Sending submission...\n")
 
        self.ez_send(self.server_peer, SubmissionPayload(EMAIL, GITHUB_URL, nonce))
 
    @lazy_wrapper(ResponsePayload)
    async def on_response(self, peer: Peer, payload: ResponsePayload):
        expected_key = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)
        try:
            sender_key = peer.public_key.key_to_bin()
        except Exception:
            print("WARNING: Could not read public key from response sender — ignoring.")
            return
 
        if sender_key != expected_key:
            print("WARNING: Ignoring response from non-server peer.")
            return
 
        print("\n==============================")
        print("SERVER RESPONSE")
        print("==============================")
        print(f"Success: {payload.success}")
        print(f"Message: {payload.message}")
        print("==============================\n")
 
        asyncio.get_event_loop().stop()
 
 
# ============================================================
# MAIN
# ============================================================
 
async def main():
    key_path = Path(KEY_FILE)
 
    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()
 
    builder.add_key("my peer", "curve25519", str(key_path))
 
    builder.add_overlay(
        "Lab1Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 5.0})],
        default_bootstrap_defs,
        {},
        [],
        -1,
    )
 
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"Lab1Community": Lab1Community},
    )
 
    await ipv8.start()
    print("IPv8 started, waiting for server peer...\n")
 
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await ipv8.stop()
 
 
if __name__ == "__main__":
    asyncio.run(main())