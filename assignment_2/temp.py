import asyncio
import logging

from tkinter import W
from typing import List
from pathlib import Path
 
from ipv8.keyvault.crypto import ECCrypto
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8

class _UnsupportedCurveFilter(logging.Filter):
    """Suppress the stream of 'Curve X is not supported' errors from old peers."""
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return "Curve" not in msg and "is not supported" not in msg
 
logging.getLogger("Lab2Community").addFilter(_UnsupportedCurveFilter())
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Lab2Community")

KEY_FILE = "assignment_1/key.pem"
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
COMMUNITY_ID_HEX = "4c61623247726f75705369676e696e6732303236"
GROUP_ID = "5c0303d6e952c77d"

NR_TO_MEMBER = {
    0: 0,
    1: 1,
    2:  "4c69624e61434c504b3a083cce420655430799b74fb41c1ca5a224e62c545bd01c399375fa30fb2fad7703f907989c049b65042ca5d1b54471691161b629cb7972aecd2cc83fe04a34bd",
}
MEMBER_TO_NR = {
    0: 0,
    1: 1,
    "4c69624e61434c504b3a083cce420655430799b74fb41c1ca5a224e62c545bd01c399375fa30fb2fad7703f907989c049b65042ca5d1b54471691161b629cb7972aecd2cc83fe04a34bd": 2
}

@vp_compile
class ChallangeRequest(VariablePayload):
    msg_id=3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ChallangeResponse(VariablePayload):
    msg_id=4
    format_list = ["varlenH", "q", "d" ]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class BundleSubmission(VariablePayload):
    msg_id=5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

@vp_compile
class RoundResult(VariablePayload):
    msg_id=6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]

@vp_compile
class ReadyPayload(VariablePayload):
    """Ready msg, to share we are ready to start the challenges. Only share when the cache is full."""
    msg_id = 99
    format_list = ["varlenHutf8"]
    names = ["group_id"]


class Lab2Community(Community, PeerObserver):
    community_id = bytes.fromhex(COMMUNITY_ID_HEX)
 
    def __init__(self, settings):
        super().__init__(settings)

        self._group_id = settings.group_id
        self._my_index = settings.my_index
        self._member_to_nr= settings.member_to_nr
        self._nr_to_member = settings.nr_to_member
        self._server_pk = settings.server_pk
        self._sk = None

        self.server_peer = None
        self._nr_to_peer = {}
        self.all_present = False
        
        self.teammates_ready = {}
        self.all_ready = False

        # self.add_message_handler(ChallangeRequest, self._on_challenge_response)
        # self.add_message_handler(ChallangeResponse, self._on_round_result)
        self.add_message_handler(ReadyPayload, self._on_ready)
    
    def started(self):
        print("-- STARTED COMMUNITY --")
        print(f"Own mid: {self.my_peer.mid.hex()}")
        print(f"My key end: {self.my_peer.public_key.key_to_bin().hex()[-20:]}")
        self.network.add_peer_observer(self)

    def on_peer_removed(self, peer: Peer) -> None:
        peer_pk = peer.public_key.key_to_bin().hex()
        print(f"PEER REMOVED: {peer}, with pk:\n{peer_pk[-20:]}")
        return

    def on_peer_added(self, peer: Peer):
        if self.all_present:
            return

        peer_pk = peer.public_key.key_to_bin().hex()
        print(f"FOUND PEER: {peer}, with pk:\n{peer_pk[-20:]}")

        if is_server(peer):
            print("SERVER FOUND\n")
            self.server_peer = peer
        
        if peer_pk in self._member_to_nr.keys():
            nr = self._member_to_nr[peer_pk]
            print(f"Found group mate: {nr}\n")
            self._nr_to_peer[nr] = peer
        
        if self.server_peer and len(self._nr_to_peer.keys()) == 3:
            self.all_present = True
            print("FOUND EVERYONE, continuing to protocol")
            self._broadcast_ready()

    @lazy_wrapper(ReadyPayload)
    def _on_ready(self, peer: Peer, payload: ReadyPayload) -> None:
        sender_key = peer.public_key.key_to_bin().hex()
        if sender_key not in self._member_to_nr.keys():
            print("ReadyPayload from unregistered peer, ignored.", payload)
            return
        
        if payload.group_id != self._group_id:
            print("ReadyPayload group id mismatch.", payload)
            return

        if self.teammates_ready[peer] != None:
            print(f"ReadyPayload from mebmer already ready: {payload}")
            return

        self.teammates_ready[peer] = self._member_to_nr[sender_key]
        print("Teammate %d ready (%d/2)", self.teammates_ready[peer], len(self.teammates_ready.keys()))

        if len(self.teammates_ready.keys()) == 3:
            print("EVERYONE READY")

    def _broadcast_ready(self) -> None:
        payload = ReadyPayload(group_id=self._group_id)
        for peer, _ in self.teammates_ready.values():
            self.ez_send(peer, payload)

        logger.debug("ReadyPayload broadcast to %d teammate(s).", len(self.teammates_ready.keys()))
        
        
def is_server(peer: Peer):
    return peer.public_key.key_to_bin().hex() == SERVER_PUBLIC_KEY_HEX

async def main():
    key_path = Path(KEY_FILE)
 
    builder = ConfigBuilder()
    builder.clear_keys()
    builder.clear_overlays()
    builder.add_key("my peer", "curve25519", str(key_path))
    builder.add_overlay(
        "Lab2Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 30, {"timeout": 5.0})],
        default_bootstrap_defs,
        {
            "community_id": COMMUNITY_ID_HEX,
            "group_id": GROUP_ID,
            "nr_to_member": NR_TO_MEMBER,
            "member_to_nr": MEMBER_TO_NR,
            "my_index": 0,
            "server_pk": SERVER_PUBLIC_KEY_HEX 
        },
        [("started",)],
        False,
    )
 
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    print("IPv8 started, waiting for server peer...\n")
 
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await ipv8.stop()
 
 
if __name__ == "__main__":
    asyncio.run(main())


