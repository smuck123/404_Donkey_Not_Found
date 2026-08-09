from html.parser import HTMLParser
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Query

from app.zabbix import ZabbixAPIError


router = APIRouter(tags=["documentation"])
DOCS_ROOT = "https://www.zabbix.com/documentation/8.0/en/manual/"


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.ignored = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "nav", "footer"}:
            self.ignored += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "nav", "footer"} and self.ignored:
            self.ignored -= 1

    def handle_data(self, data: str) -> None:
        if not self.ignored and data.strip():
            self.parts.append(data.strip())


@router.get("/documentation", operation_id="read_zabbix_documentation")
async def documentation(
    path: str = Query("", max_length=300, description="Path below the Zabbix 8.0 English manual"),
    max_chars: int = Query(20000, ge=1000, le=50000),
) -> dict[str, str | int]:
    clean = path.strip().strip("/")
    if clean.startswith(("http:", "https:")) or ".." in clean:
        raise ZabbixAPIError("Documentation path is not allowed", status_code=400)
    encoded = "/".join(quote(part, safe="-_~.") for part in clean.split("/") if part)
    url = DOCS_ROOT + encoded
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "Donkey-Zabbix-Tools/0.3"})
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise ZabbixAPIError("Zabbix documentation request timed out", status_code=504) from exc
    except httpx.HTTPError as exc:
        raise ZabbixAPIError("Unable to retrieve Zabbix documentation", status_code=502) from exc

    parser = TextExtractor()
    parser.feed(response.text)
    text = "\n".join(parser.parts)
    return {"url": str(response.url), "characters": min(len(text), max_chars), "content": text[:max_chars]}

