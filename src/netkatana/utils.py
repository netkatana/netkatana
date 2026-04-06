from urllib.parse import urlparse


def parse_host(target: str) -> str:
    """Extract the host (and port if present) from a URL or bare hostname."""
    if "://" not in target:
        target = f"https://{target}"
    return urlparse(target).netloc
