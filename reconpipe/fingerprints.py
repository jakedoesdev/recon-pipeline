"""Subdomain takeover fingerprints — modeled after can-i-take-over-xyz."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TakeoverFingerprint:
    service: str
    cname_patterns: list[str]
    body_patterns: list[str]
    nxdomain_vulnerable: bool = False


BUILTIN_FINGERPRINTS: list[TakeoverFingerprint] = [
    TakeoverFingerprint(
        service="s3",
        cname_patterns=[".s3.amazonaws.com", ".s3-website"],
        body_patterns=["NoSuchBucket", "The specified bucket does not exist"],
    ),
    TakeoverFingerprint(
        service="azure_blob",
        cname_patterns=[".blob.core.windows.net"],
        body_patterns=["BlobNotFound", "The specified container does not exist"],
    ),
    TakeoverFingerprint(
        service="azure_webapp",
        cname_patterns=[".azurewebsites.net"],
        body_patterns=["404 Web Site not found", "Microsoft Azure App Service"],
    ),
    TakeoverFingerprint(
        service="github_pages",
        cname_patterns=[".github.io"],
        body_patterns=["There isn't a GitHub Pages site here", "For root URLs"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="heroku",
        cname_patterns=[".herokuapp.com", ".herokudns.com", ".herokussl.com"],
        body_patterns=["No such app", "no-such-app"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="shopify",
        cname_patterns=[".myshopify.com"],
        body_patterns=["Sorry, this shop is currently unavailable", "Only one step left"],
    ),
    TakeoverFingerprint(
        service="fastly",
        cname_patterns=[".fastly.net", ".fastlylb.net"],
        body_patterns=["Fastly error: unknown domain"],
    ),
    TakeoverFingerprint(
        service="pantheon",
        cname_patterns=[".pantheonsite.io"],
        body_patterns=["404 error unknown site", "The gods are wise"],
    ),
    TakeoverFingerprint(
        service="tumblr",
        cname_patterns=[".tumblr.com"],
        body_patterns=["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    ),
    TakeoverFingerprint(
        service="unbounce",
        cname_patterns=[".unbouncepages.com"],
        body_patterns=["The requested URL was not found on this server"],
    ),
    TakeoverFingerprint(
        service="wordpress",
        cname_patterns=[".wordpress.com"],
        body_patterns=["Do you want to register"],
    ),
    TakeoverFingerprint(
        service="surge",
        cname_patterns=[".surge.sh"],
        body_patterns=["project not found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="bitbucket",
        cname_patterns=[".bitbucket.io"],
        body_patterns=["Repository not found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="ghost",
        cname_patterns=[".ghost.io"],
        body_patterns=["The thing you were looking for is no longer here"],
    ),
    TakeoverFingerprint(
        service="netlify",
        cname_patterns=[".netlify.app", ".netlify.com"],
        body_patterns=["Not Found - Request ID"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="fly_io",
        cname_patterns=[".fly.dev"],
        body_patterns=["404 Not Found"],
        nxdomain_vulnerable=True,
    ),
    TakeoverFingerprint(
        service="cloudfront",
        cname_patterns=[".cloudfront.net"],
        body_patterns=["Bad request", "ERROR: The request could not be satisfied"],
    ),
]
