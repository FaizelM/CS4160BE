import socket
import asyncio
from ipv8.configuration import default_bootstrap_defs

BOOTSTRAP_NODES = [
    ("130.161.119.206", 6421),
    ("130.161.119.206", 6422),
    ("131.180.27.155", 6423),
    ("131.180.27.156", 6424),
    ("131.180.27.161", 6427),
    ("130.161.119.215", 6525),
    ("dispersy1.tribler.org", 6421),
    ("dispersy1.st.tudelft.nl", 6421),
    ("dispersy2.st.tudelft.nl", 6422),
]

async def check(host, port):
    print(f"Checking {host}:{port}...", end=" ")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"FAILED (DNS: {e})")
        return

    try:
        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(ip, port)
        )
        transport.sendto(b"\x00")
        transport.close()
        print(f"OK ({ip})")
    except Exception as e:
        print(f"FAILED (UDP: {e})")

async def main():
    for host, port in BOOTSTRAP_NODES:
        await check(host, port)

asyncio.run(main())