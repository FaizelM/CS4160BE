import sys
import time
import hashlib
import argparse

from pathlib import Path

DIFFICULTY_BITS = 28            # num of required leading zeros
PROGRESS_INTERVAL = 1_000_000   # print progress every x attempts
NONCE_FILE = Path("nonce.txt")  # persist result 

class POW():
    def __init__(self, email: str, url: str):
        self.email = email
        self.url = url
        self._prefix = self._build_prefix(self.email, self.url)

    def _build_prefix(self, email: str, url: str) -> bytes:
        """Build prefix of the hash, this doesn't change between hash attempts"""
        return email.encode("utf-8") + b"\n" + url.encode("utf-8") + b"\n"

    def check_difficulty(self, digest: bytes, bits: int = DIFFICULTY_BITS) -> bool:
        """Check if this nonce satisfies the set difficulty"""
        # Split the number of bits in zero bytes, and bytes that are not fully zero
        full_bytes, remainder = divmod(bits, 8)

        # Check that the full zero bytes are really zero
        if any(digest[i] != 0 for i in range(full_bytes)):
            return False

        # The remainder bytes should have the correct number of zeros
        # for our case (28), is that 0XF0 & remainder byte == 0
        if remainder:
            mask = 0xFF << (8 - remainder) & 0xFF
            if digest[full_bytes] & mask != 0:
                return False

        return True


    def mine(self) -> int:
        """Search for a nonce that satisfies the difficulty"""
        nonce = 0 
        t0 = time.monotonic()

        print(f"[PoW] Mining with difficulty={DIFFICULTY_BITS} bits")
        print(f"[PoW] Email : {self.email}")
        print(f"[PoW] URL   : {self.url}")

        while True:
            # Encode nonce as signed 64-bit big-endian
            nonce_bytes = nonce.to_bytes(8, "big", signed=True)
            digest = hashlib.sha256(self._prefix + nonce_bytes).digest()

            if self.check_difficulty(digest):
                elapsed = time.monotonic() - t0
                rate = (nonce + 1) / elapsed / 1_000_000
                print(
                    f"\n[PoW] Found nonce={nonce} after {nonce + 1:,} "
                    f"attempts in {elapsed:.1f}s  ({rate:.2f} MH/s)"
                )
                print(f"[PoW] Hash: {digest.hex()}")
                return nonce

            nonce += 1
            if nonce % PROGRESS_INTERVAL == 0:
                elapsed = time.monotonic() - t0
                rate = (nonce ) / elapsed / 1_000_000
                print(
                    f"[PoW] {nonce:>12,}  elapsed={elapsed:6.1f}s  {rate:.2f} MH/s",
                    flush=True,
                )

            if nonce >= 2**63:
                raise OverflowError("This should never happen!")


    def verify(self, nonce: int) -> bool:
        """Verify that a nonce with the current mail and url"""
        nonce_bytes = nonce.to_bytes(8, "big", signed=True)
        digest = hashlib.sha256(self._prefix + nonce_bytes).digest()
        return self.check_difficulty(digest)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 1 PoW miner")
    parser.add_argument("--email", required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    email: str = args.email.strip()
    url: str = args.url.strip()

    # Check that I'm not stupid
    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        sys.exit(f"[PoW] email must end with @tudelft.nl or @student.tudelft.nl, got: {email}")
    if not url or any(c <= " " for c in url):
        sys.exit("[PoW] URL must be non-empty and contain no whitespace/control chars")

    pow = POW(email=email, url=url)

    if NONCE_FILE.exists():
        saved = int(NONCE_FILE.read_text().strip())
        if pow.verify(saved):
            print(f"[PoW] Loaded valid nonce from {NONCE_FILE}: {saved}")
            return
        else:
            print(f"[PoW] Saved nonce {saved} does not verify. Re-mining…")

    nonce = pow.mine()
    NONCE_FILE.write_text(str(nonce))
    print(f"[PoW] Nonce saved to {NONCE_FILE}")


if __name__ == "__main__":
    main()