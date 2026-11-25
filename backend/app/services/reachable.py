import socket

from app.config import PUBLIC_BACKEND_URL


def _lan_ip() -> str:
    """Best-effort LAN IP of this machine (so a monitored website on another
    device can reach the backend). Falls back to the loopback address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.1.1", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def reachable_backend_url() -> str:
    """Base URL the monitored website's browser can reach.

    PUBLIC_BACKEND_URL is the admin-configured address (used as-is when it is
    not loopback). With the dev default (localhost/127.0.0.1) it only works
    when the monitored website runs on the SOC machine itself, so fall back to
    this machine's LAN IP so a website on another device gets a real host.
    Configure PUBLIC_BACKEND_URL to a public HTTPS domain for production.
    """
    url = (PUBLIC_BACKEND_URL or "").strip().rstrip("/")
    if url and "localhost" not in url and "127.0.0.1" not in url:
        return url
    return f"http://{_lan_ip()}:8000"