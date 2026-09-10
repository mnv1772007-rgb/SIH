"""Safe extraction and static comparison of HTML links."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.href: str | None = None
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a" and self.href is None:
            self.href = dict(attrs).get("href")
            self.text = []

    def handle_data(self, data: str) -> None:
        if self.href is not None:
            self.text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self.href is not None:
            self.links.append({"text": " ".join("".join(self.text).split()), "href": self.href})
            self.href, self.text = None, []


def extract_html_links(html: str) -> list[dict[str, str]]:
    parser = _LinkParser()
    parser.feed(html)
    parser.close()
    return parser.links


def analyze_html_link(link: dict[str, str]) -> dict[str, object]:
    visible_text, actual_url = (link.get("text") or "").strip(), (link.get("href") or "").strip()
    actual = urlparse(actual_url)
    visible = urlparse(visible_text)
    visible_domain = visible.hostname.lower() if visible.scheme.lower() in {"http", "https"} and visible.hostname else None
    actual_domain = actual.hostname.lower() if actual.hostname else None
    dangerous = actual.scheme.lower() in {"javascript", "data", "vbscript", "file"}
    return {
        "visible_text": visible_text, "actual_url": actual_url,
        "visible_text_is_url": visible_domain is not None, "visible_domain": visible_domain,
        "actual_domain": actual_domain,
        "destination_mismatch": bool(visible_domain and actual_domain and visible_domain != actual_domain),
        "is_dangerous_scheme": dangerous,
        "dangerous_scheme_type": actual.scheme.lower() if dangerous else None,
    }
