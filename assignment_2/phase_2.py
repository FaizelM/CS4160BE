import os
import sys
import asyncio
import logging

from typing import List
from pathlib import Path
from dotenv import load_dotenv

from phase_2_community import Lab2Community

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, BootstrapperDefinition, Bootstrapper, default_bootstrap_defs
from ipv8_service import IPv8
from ipv8.util import run_forever


KEY_FILE  = Path("assignment_1", "key.pem")
GROUP_ID  = "21" # TODO
 
MY_INDEX  = 0 # own position in the list below (0, 1, or 2)
MEMBER_KEYS: List[bytes] = [  #TODO
    bytes.fromhex("aabbcc00" * 8),  # member 0
    bytes.fromhex("ddeeff11" * 8),  # member 1
    bytes.fromhex("112233aa" * 8),  # member 2
]
 
load_dotenv()
def _require_env(key: str) -> str:
    value = os.getenv(key)
    if not value:
        sys.exit(f"ERROR: environment variable {key!r} is not set in .env")
    return value

COMMUNITY_ID      = bytes.fromhex(_require_env("COMMUNITY_ID_ASS2"))
SERVER_PUBLIC_KEY = bytes.fromhex(_require_env("SERVER_PUBLIC_KEY_ASS2"))
 
async def _run() -> None:
    config = (
        ConfigBuilder()
        .clear_keys()
        .add_key("my_peer", "curve25519", str(KEY_FILE))
        .clear_overlays()
        .add_overlay(
            "Lab2Community",
            "my_peer",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs + [
                BootstrapperDefinition(Bootstrapper.UDPBroadcastBootstrapper, {})
            ],
            {
                "community_id": COMMUNITY_ID,
                "group_id": GROUP_ID,
                "member_keys": MEMBER_KEYS,
                "my_index": MY_INDEX,
                "server_pk": SERVER_PUBLIC_KEY
            }, 
            [("run_all_rounds",)],
        )
        .finalize()
    )
 
    ipv8 = IPv8(config, extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    await run_forever() 
 
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    asyncio.run(_run())
 
