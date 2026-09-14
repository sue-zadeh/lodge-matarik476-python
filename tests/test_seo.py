import json
import re
from xml.etree import ElementTree

import pytest

from app.seo import SITE_URL


def test_public_pages_have_unique_metadata_and_stable_canonicals(client):
    titles, descriptions = set(), set()
    for path in ("/", "/about", "/our_story", "/contact"):
        response = client.get(path + "?utm_source=test", base_url=SITE_URL)
        assert response.status_code == 200
        assert "X-Robots-Tag" not in response.headers
        html = response.get_data(as_text=True)
        assert f'href="{SITE_URL}{path}"' in html
        assert '<meta name="robots" content="index, follow">' in html
        titles.add(re.search(r"<title>(.*?)</title>", html, re.S).group(1).strip())
        descriptions.add(re.search(r'<meta name="description"\s+content="([^"]+)"', html).group(1).strip())
    assert len(titles) == len(descriptions) == 4


def test_sitemap_lists_only_public_pages_and_robots_links_to_it(client):
    response = client.get("/sitemap.xml", base_url=SITE_URL)
    assert response.mimetype == "application/xml"
    root = ElementTree.fromstring(response.data)
    locations = {element.text for element in root.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")}
    assert locations == {SITE_URL + path for path in ("/", "/about", "/our_story", "/contact")}
    robots = client.get("/robots.txt", base_url=SITE_URL)
    assert robots.mimetype == "text/plain"
    assert f"Sitemap: {SITE_URL}/sitemap.xml" in robots.get_data(as_text=True)


@pytest.mark.parametrize("path", ["/login", "/register", "/forgot-password", "/admin/users", "/member/files", "/missing-page"])
def test_private_and_error_responses_are_not_indexed(client, path):
    response = client.get(path, base_url=SITE_URL)
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
    assert b'rel="canonical"' not in response.data


def test_local_and_alternate_hosts_are_not_indexed(client):
    for origin in ("http://localhost:5000", "https://preview.example.test"):
        response = client.get("/contact", base_url=origin)
        assert response.headers["X-Robots-Tag"] == "noindex, nofollow"
        assert f'href="{SITE_URL}/contact"' in response.get_data(as_text=True)
        assert b"Disallow: /" in client.get("/robots.txt", base_url=origin).data


def test_homepage_has_organization_markup_and_a_main_heading(client):
    html = client.get("/", base_url=SITE_URL).get_data(as_text=True)
    organization = json.loads(re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S).group(1))
    assert organization["@type"] == "Organization"
    assert organization["url"] == SITE_URL + "/"
    assert organization["address"]["streetAddress"] == "45 Neilson Street"
    assert "aggregateRating" not in organization
    assert len(re.findall(r"<h1\b", html)) == 1
