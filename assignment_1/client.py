import os
import sys
import logging
import asyncio
import argparse

from proof_of_work import POW

from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs, BootstrapperDefinition, Bootstrapper
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.messaging.lazy_payload import vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.util import run_forever

class _UnsupportedCurveFilter(logging.Filter):
    """Prevent the stream of not supported curve errors"""
    def filter(self, record: logging.LogRecord) -> bool:
        return "Curve" not in record.getMessage() and "is not supported" not in record.getMessage()
 
logging.getLogger("Lab1Community").addFilter(_UnsupportedCurveFilter())
logging.basicConfig(level=logging.DEBUG)


load_dotenv()
def _require_env(key: str) -> str:
    """Read a required environment variable; exit with a clear error if missing."""
    value = os.getenv(key)
    if not value:
        sys.exit(f"ERROR: {key!r} is not set in .env")
    return value

COMMUNITY_ID = bytes.fromhex(_require_env("COMMUNITY_ID_ASS1"))
SERVER_PUBLIC_KEY = bytes.fromhex(_require_env("SERVER_PUBLIC_KEY_ASS1"))

KEY_FILE = Path("assignment_1", "key.pem")
DISCOVERY_TIMEOUT = 300.0   
RESPONSE_TIMEOUT  = 120.0    

@dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int

@vp_compile
@dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool 
    message: str

    names = ["success", "message"]
    format_list = ["?", "varlenHutf8"]

class Lab1Community(Community, PeerObserver):
    community_id = COMMUNITY_ID
    server_public_key = SERVER_PUBLIC_KEY

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.add_message_handler(SubmissionPayload, self.on_submission)

        self._email: str = settings.email 
        self._github_url: str = settings.github_url
        self._nonce: int = settings.nonce 

    def on_started(self) -> None:
        print("[Community] started")
        self.network.add_peer_observer(self)

    def _is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == self.server_public_key 
    
    def on_peer_added(self, peer: Peer) -> None:
        if not self._is_server(peer):
            print(f"[Community] peer is not server: {peer}")
            return

        print(f"[Community] Server found: {peer}", flush=True)
        assert self._nonce is not None
        assert self._email is not None
        assert self._github_url is not None

        print(f"[Community] Sending submission email={self._email}, github_url={self._github_url}, nonce={self._nonce}")
        payload = SubmissionPayload(email=self._email, github_url=self._github_url, nonce=self._nonce)
        self.ez_send(peer, payload)

    def on_peer_removed(self, peer: Peer) -> None:
        if self._is_server(peer):
            print("[Community] Server disconnected")
        else:
            print("[Coummunity] Peer disconnected")

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        if not self._is_server(peer):
            print(f"[Community] Ignoring response from peer (not server): {peer}, payload:\n{payload}")
            return

        status = "ACCEPTED" if payload.success else "REJECTED"
        print(f"\n[Community] Server response: {status}")
        print(f"[Community] Message:\n{payload}\n")
        if payload.success:
            exit(0)
        else:
            exit(1)

    @lazy_wrapper(SubmissionPayload)
    def on_submission(self, peer: Peer, payload: SubmissionPayload) -> None:
        print(f"[Community] ignoring submission from peer {peer}, payload was:\n{payload}")

def get_nonce(email: str, github_url: str) -> int:
    pow_solver = POW(email=email, url=github_url)

    if pow_solver.NONCE_FILE.exists():
        candidate = int(pow_solver.NONCE_FILE.read_text().strip())
        if pow_solver.verify(candidate):
            print(f"[Client] Loaded valid nonce from {pow_solver.NONCE_FILE}: {candidate}")
            return candidate
        print(f"[Client] Cached nonce {candidate} is invalid. Re-mining")

    print("[Client] Starting PoW mining")
    nonce = pow_solver.mine()
    pow_solver.NONCE_FILE.write_text(str(nonce))
    print(f"[Client] Nonce persisted to {pow_solver.NONCE_FILE}")
    return nonce


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 1 IPv8 client")
    parser.add_argument("--email", required=False)
    parser.add_argument("--url",   required=False)
    return parser.parse_args()

async def main():
    args = _parse_args()

    email = (args.email or os.getenv("EMAIL") or "").strip()
    github_url  = (args.url or os.getenv("URL") or "").strip()

    if not email:
        sys.exit("ERROR: No email provided")
    if not github_url:
        sys.exit("ERROR: No URL provided via --url or URL env var")

    # Verify im not stupid
    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        sys.exit(f"ERROR: email must end with @tudelft.nl or @student.tudelft.nl, got: {email!r}")
    if not github_url or any(c <= " " for c in github_url):
        sys.exit("ERROR: URL must be non-empty and contain no whitespace/control characters")

    # Handle ipv8
    nonce = get_nonce(email=email, github_url=github_url)
    config = (
        ConfigBuilder()
        .clear_keys()
        .add_key("my peer", "curve25519", str(KEY_FILE))
        .clear_overlays()
        .add_overlay(
            "Lab1Community",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs + [BootstrapperDefinition(Bootstrapper.UDPBroadcastBootstrapper, {})],
            {
                "email": email,
                "github_url": github_url,
                "nonce": nonce,
            },
            [("on_started",)],
        )
        .finalize()
    )

    ipv8 = IPv8(config, extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    await run_forever()

if __name__ == "__main__":
    asyncio.run(main())