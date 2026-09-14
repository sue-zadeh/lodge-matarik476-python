"""Search metadata for public pages; member and reset pages stay unindexed."""

from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from flask import Response, request, url_for


SITE_URL = "https://lodgematariki476.co.nz"
PUBLIC_ENDPOINTS = ("home", "about", "our_story", "contact")


def is_public_origin():
    origin = urlsplit(SITE_URL)
    return request.scheme == origin.scheme and request.host.lower() == origin.netloc


def register_seo(app):
    @app.context_processor
    def public_search_metadata():
        is_public = request.endpoint in PUBLIC_ENDPOINTS
        canonical = SITE_URL + url_for(request.endpoint) if is_public else None
        organization = None
        if request.endpoint == "home":
            organization = {
                "@context": "https://schema.org",
                "@type": "Organization",
                "@id": SITE_URL + "/#organization",
                "name": "Lodge Matariki 476",
                "url": SITE_URL + "/",
                "logo": SITE_URL + "/static/img/logo1.png",
                "email": app.config["CONTACT_EMAIL"],
                "address": {
                    "@type": "PostalAddress",
                    "streetAddress": "45 Neilson Street",
                    "addressLocality": "Onehunga, Auckland",
                    "addressRegion": "Auckland",
                    "postalCode": "1061",
                    "addressCountry": "NZ",
                },
            }
        return {
            "seo_canonical_url": canonical,
            "seo_site_url": SITE_URL,
            "seo_robots": "index, follow" if is_public and is_public_origin() else "noindex, nofollow",
            "seo_organization": organization,
        }

    @app.after_request
    def private_search_headers(response):
        public_resources = {*PUBLIC_ENDPOINTS, "static", "sitemap", "robots"}
        if request.endpoint not in public_resources or not is_public_origin() or response.status_code >= 400:
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/sitemap.xml")
    def sitemap():
        urls = "".join(
            f"<url><loc>{escape(SITE_URL + url_for(endpoint))}</loc></url>"
            for endpoint in PUBLIC_ENDPOINTS
        )
        return Response(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + urls + '</urlset>',
            mimetype="application/xml",
        )

    @app.get("/robots.txt")
    def robots():
        if not is_public_origin():
            return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")
        # Let crawlers see noindex on login/reset pages. Authentication protects member data.
        return Response(
            f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n",
            mimetype="text/plain",
        )
