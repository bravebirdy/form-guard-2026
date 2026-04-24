from __future__ import annotations

import ipaddress
from typing import Iterable

from fastapi import Request

from app.core.settings import settings


def _parse_cidrs(csv: str) -> list[ipaddress._BaseNetwork]:
    cidrs = [c.strip() for c in (csv or "").split(",") if c.strip()]
    out: list[ipaddress._BaseNetwork] = []
    for c in cidrs:
        out.append(ipaddress.ip_network(c, strict=False))
    return out


def _first_forwarded_for(x_forwarded_for: str | None) -> str | None:
    if not x_forwarded_for:
        return None
    parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
    return parts[0] if parts else None


def _is_trusted_proxy(ip_str: str, trusted: Iterable[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in trusted)


def get_client_ip(request: Request) -> str:
    """
    Returns best-effort client IP.
    If TRUSTED_PROXY_CIDRS is configured and the remote peer is trusted, uses X-Forwarded-For first hop.
    """
    client_host = request.client.host if request.client else ""
    trusted = _parse_cidrs(settings.trusted_proxy_cidrs)

    if client_host and trusted and _is_trusted_proxy(client_host, trusted):
        xff = request.headers.get("x-forwarded-for")
        first = _first_forwarded_for(xff)
        if first:
            return first

        cf = request.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()

    return client_host

