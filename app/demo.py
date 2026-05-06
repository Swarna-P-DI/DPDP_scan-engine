from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from app.core.scanner import ScanService


async def _run(path: Path) -> dict:
    service = ScanService()
    return await service.scan_bytes(path.name, path.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local SCAN + RAID demo.")
    parser.add_argument("file", nargs="?", default="test_data/scan_raid/sample_kyc.csv")
    args = parser.parse_args()
    report = asyncio.run(_run(Path(args.file)))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
