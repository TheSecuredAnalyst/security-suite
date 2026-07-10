"""
Rules of Engagement (ROE) validation — from Automated_VAPT.

Validates scan targets against allowed and forbidden CIDR scopes
before any scanning begins. Hostnames cannot be IP-validated without
DNS resolution, so they receive a warning but are not blocked.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def _parse_networks(cidrs: list[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for c in cidrs or []:
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


class RulesOfEngagement:
    """
    Validates scan targets against an approved scope.

    Usage:
        roe = RulesOfEngagement(
            allowed_cidrs=["10.0.0.0/8", "192.168.1.0/24"],
            forbidden_cidrs=["192.168.1.1/32"],   # gateway — do not scan
        )
        warnings, ok = roe.evaluate(["192.168.1.0/24"])
        if warnings:
            for w in warnings:
                print(f"ROE Warning: {w}")
    """

    def __init__(
        self,
        allowed_cidrs: list[str] | None = None,
        forbidden_cidrs: list[str] | None = None,
    ):
        self.allowed_nets = _parse_networks(allowed_cidrs or [])
        self.forbidden_nets = _parse_networks(forbidden_cidrs or [])

    def evaluate(self, targets: Iterable[str]) -> tuple[list[str], list[str]]:
        """
        Validate targets against ROE.

        Returns:
            (warnings, allowed_targets)
            - warnings: human-readable scope violations
            - allowed_targets: targets as provided (not mutated)
        """
        warnings: list[str] = []
        allowed: list[str] = []

        for raw in targets:
            t = str(raw).strip()
            if not t:
                continue

            try:
                if "/" in t:
                    net = ipaddress.ip_network(t, strict=False)
                    for fn in self.forbidden_nets:
                        if net.overlaps(fn):
                            warnings.append(
                                f"[ROE] Target {t} overlaps forbidden scope {fn}"
                            )
                    if self.allowed_nets and not any(net.overlaps(an) for an in self.allowed_nets):
                        warnings.append(f"[ROE] Target {t} is outside the allowed scope")
                else:
                    ip = ipaddress.ip_address(t)
                    for fn in self.forbidden_nets:
                        if ip in fn:
                            warnings.append(
                                f"[ROE] Target {t} is in forbidden scope {fn}"
                            )
                    if self.allowed_nets and not any(ip in an for an in self.allowed_nets):
                        warnings.append(f"[ROE] Target {t} is outside the allowed scope")
            except ValueError:
                warnings.append(
                    f"[ROE] Target '{t}' is not an IP/CIDR — "
                    "scope validation skipped (hostname)"
                )

            allowed.append(t)

        return warnings, allowed

    @property
    def is_configured(self) -> bool:
        return bool(self.allowed_nets or self.forbidden_nets)
