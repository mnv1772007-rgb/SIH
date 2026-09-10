from urllib.parse import urlsplit, urlunsplit


def normalize_url(url):
    """
    Normalize a URL for comparison and deduplication.
    This does NOT visit the URL.
    """

    url = url.strip()

    if not url:
        return None

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        if not scheme or not hostname:
            return None

        # Preserve port if explicitly present
        # urlsplit.hostname removes IPv6 brackets; add them back when rebuilding.
        netloc = f"[{hostname}]" if ":" in hostname else hostname

        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        # Rebuild normalized URL
        normalized = urlunsplit(
            (
                scheme,
                netloc,
                parsed.path or "",
                parsed.query or "",
                ""
            )
        )

        return normalized

    except ValueError:
        return None


def deduplicate_urls(urls):

    unique_urls = []
    seen = set()

    for url in urls:

        normalized = normalize_url(url)

        if normalized and normalized not in seen:

            seen.add(normalized)
            unique_urls.append(normalized)

    return unique_urls


if __name__ == "__main__":

    test_urls = [
        "HTTPS://Example.com/verify",
        "https://example.com/verify",
        "https://example.com/verify/",
        "https://example.com/login",
        "https://Example.com/login"
    ]

    result = deduplicate_urls(test_urls)

    print("========== URL NORMALIZATION ==========")

    for url in result:
        print(url)

    print("=======================================")
