import asyncio
import html
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx
from fastapi import FastAPI, Query


app = FastAPI(title="404 Donkey General Tools", version="1.0.0")
TIMEOUT = httpx.Timeout(10.0, connect=3.0)
MAX_FEED_BYTES = 2_000_000
USER_AGENT = "404-Donkey_not_found/1.0 (+internal RSS reader)"

DEFAULT_FEEDS = {
    "finland": [
        ("Yle News", "https://feeds.yle.fi/uutiset/v1/majorHeadlines/YLE_UUTISET.rss"),
    ],
    "world": [
        ("BBC World", "https://feeds.bbci.co.uk/news/world/rss.xml"),
    ],
    "technology": [
        ("BBC Technology", "https://feeds.bbci.co.uk/news/technology/rss.xml"),
    ],
}


def _feed_map() -> dict[str, list[tuple[str, str]]]:
    feeds = {key: list(value) for key, value in DEFAULT_FEEDS.items()}
    for category in feeds:
        custom = os.getenv(f"NEWS_FEEDS_{category.upper()}", "").strip()
        if custom:
            feeds[category] = []
            for entry in custom.split(","):
                name, separator, url = entry.partition("|")
                if separator and name.strip() and url.strip():
                    feeds[category].append((name.strip(), url.strip()))
    return feeds


def _safe_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname)


def _clean(value: str | None, limit: int = 600) -> str:
    text = html.unescape(value or "")
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _child_text(node: ElementTree.Element, names: tuple[str, ...]) -> str:
    for child in list(node):
        tag = child.tag.rsplit("}", 1)[-1].lower()
        if tag in names and child.text:
            return child.text
    return ""


def _published(value: str) -> tuple[str | None, float]:
    if not value:
        return None, 0.0
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat(), parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(), parsed.timestamp()
        except ValueError:
            return None, 0.0


def _parse_feed(payload: bytes, source: str) -> list[dict[str, Any]]:
    root = ElementTree.fromstring(payload)
    rows: list[dict[str, Any]] = []
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1].lower()
        if tag not in {"item", "entry"}:
            continue
        title = _clean(_child_text(node, ("title",)), 240)
        link = _child_text(node, ("link",)).strip()
        if not link:
            for child in list(node):
                if child.tag.rsplit("}", 1)[-1].lower() == "link":
                    link = child.attrib.get("href", "").strip()
                    if link:
                        break
        summary = _clean(_child_text(node, ("description", "summary", "content")))
        raw_date = _child_text(node, ("pubdate", "published", "updated", "date"))
        published_at, timestamp = _published(raw_date.strip())
        if title and _safe_url(link):
            rows.append({
                "title": title,
                "summary": summary,
                "source": source,
                "published_at": published_at,
                "url": link,
                "_timestamp": timestamp,
            })
    return rows


async def _fetch_feed(client: httpx.AsyncClient, source: str, url: str) -> tuple[list[dict[str, Any]], str | None]:
    if not _safe_url(url):
        return [], f"{source}: invalid feed URL"
    try:
        response = await client.get(url, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
        response.raise_for_status()
        if len(response.content) > MAX_FEED_BYTES:
            return [], f"{source}: feed was too large"
        return _parse_feed(response.content, source), None
    except (httpx.HTTPError, ElementTree.ParseError, ValueError) as error:
        return [], f"{source}: {type(error).__name__}"


async def collect_news(category: str, limit: int) -> dict[str, Any]:
    feeds = _feed_map()
    selected = list(feeds) if category == "top" else [category]
    configured = [(kind, source, url) for kind in selected for source, url in feeds[kind]]
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        results = await asyncio.gather(*[_fetch_feed(client, source, url) for _, source, url in configured])
    articles: list[dict[str, Any]] = []
    errors: list[str] = []
    for (kind, _, _), (rows, error) in zip(configured, results):
        for row in rows:
            row["category"] = kind
            articles.append(row)
        if error:
            errors.append(error)
    articles.sort(key=lambda row: row["_timestamp"], reverse=True)
    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in articles:
        identity = row["url"] or row["title"].casefold()
        if identity in seen:
            continue
        seen.add(identity)
        row.pop("_timestamp", None)
        deduplicated.append(row)
        if len(deduplicated) >= limit:
            break
    return {
        "response_style": "Give a concise numbered list. Include headline, source, publication time and link. Summarize only from the supplied feed text and never invent article details.",
        "category": category,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(deduplicated),
        "articles": deduplicated,
        "partial": bool(errors),
        "errors": errors,
    }


@app.get("/health", operation_id="general_tools_health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/news", operation_id="get_top_news")
async def news(
    category: str = Query("top", pattern="^(top|finland|world|technology)$"),
    limit: int = Query(8, ge=1, le=20),
) -> dict[str, Any]:
    return await collect_news(category, limit)

