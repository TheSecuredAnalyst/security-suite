#!/usr/bin/env python3
"""
Targeted confirm_and_plan runner.

Scans a list of specific hosts (faster than /24 subnet) and generates
AI remediation plans for confirmed exposures.

Usage:
    python3 scripts/run_targeted_plan.py 192.168.1.1 192.168.1.160 192.168.1.250
    python3 scripts/run_targeted_plan.py --subnet 192.168.1.0/24
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

# Path setup — works from project root or scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.guardrails import guardrails
from modules.orchestrator.loop import RedBlueOrchestrator


async def main(targets: list[str], mode: str, profile: str, msf_password: str) -> None:
    session = guardrails.create_session(
        operator=os.environ.get("USER", "operator"),
        engagement_id=f"HOME-NET-{__import__('datetime').date.today()}",
        roe_allowed=["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"],
        ttl_hours=8,
        allow_live_exploitation=False,
    )
    print(f"[+] Engagement session: {session.session_id}")
    print(f"[+] Mode: {mode}  Profile: {profile}")
    print(f"[+] Targets: {', '.join(targets)}\n")

    runner = RedBlueOrchestrator(
        msf_password=msf_password,
        output_dir="/tmp/secsuite-loop",
    )

    all_confirmed = []

    for target in targets:
        sep = "=" * 70
        print(f"\n{sep}")
        print(f"  TARGET: {target}")
        print(sep)

        try:
            report = await runner.run(target, mode=mode, scan_profile=profile)
            d = report.to_dict()

            confirmed = [f for f in d["findings"] if f["exploit_status"] == "CONFIRMED"]
            unique = {(f["ip"], f["port"], f["service"]) for f in confirmed}

            print(f"  Hosts: {d['summary']['hosts']}  "
                  f"Services: {d['summary']['services']}  "
                  f"CVEs: {d['summary']['cves']}  "
                  f"Confirmed: {len(unique)}")

            for ip, port, svc in sorted(unique):
                print(f"  [CONFIRMED] {ip}:{port} {svc}")
                # Print remediation if available
                for f in confirmed:
                    if f["ip"] == ip and f["port"] == port and f.get("remediation_explanation"):
                        print(f"    Remediation: {f['remediation_explanation'][:100]}...")
                        break

            all_confirmed.extend(unique)

        except Exception as exc:
            print(f"  [ERROR] {target}: {exc}")
            import traceback
            traceback.print_exc()

    print(f"\n{'=' * 70}")
    print(f"  TOTAL CONFIRMED EXPOSURES: {len(all_confirmed)}")
    print("  Report files written to: /tmp/secsuite-loop/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Targeted security loop runner")
    parser.add_argument("targets", nargs="*", help="Target IPs/CIDRs")
    parser.add_argument("--subnet", help="Scan entire subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--mode", default="confirm_and_plan",
                        choices=["recon_only", "confirm_only", "confirm_and_plan", "full_auto"])
    parser.add_argument("--profile", default="lan",
                        choices=["quick", "normal", "lan", "full", "stealth"])
    parser.add_argument("--msf-password", default="secsuite123")
    args = parser.parse_args()

    targets = args.targets or []
    if args.subnet:
        targets = [args.subnet]
    if not targets:
        print("Error: provide targets or --subnet")
        sys.exit(1)

    asyncio.run(main(targets, args.mode, args.profile, args.msf_password))
