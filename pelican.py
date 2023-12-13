# -*- python -*-

import re
import sys
import warnings
from functools import lru_cache
from os.path import isfile
from random import shuffle

from urllib3.util import (Url, parse_url)

try:
    from scitokens import SciToken
except ModuleNotFoundError:
    class SciToken():  # should not match
        pass

import requests

KNOWN_FEDERATIONS = {
    "osdf": "osg-htc.org",
}
DEFAULT_FEDERATION = "OSDF"


def make_url(host, path=None, scheme=None):
    parsed = parse_url(host)
    if scheme is None and parsed.port in [80, 8000, 8080]:
        scheme = "http"
    elif scheme is None:
        scheme = "https"
    if path:
        path = "/".join((parsed.path or "", path or ""))
    else:
        path = parsed.path
    return Url(
        scheme=parsed.scheme or scheme,
        auth=parsed.auth,
        host=parsed.host,
        port=parsed.port,
        path=path,
        query=parsed.query,
        fragment=parsed.fragment,
    ).url


@lru_cache()
def _pelican_configuration(federation):
    configurl = make_url(
        federation,
        ".well-known/pelican-configuration",
        scheme="https",
    )
    resp = requests.get(configurl)
    resp.raise_for_status()
    return resp.json()


def _pelican_director_endpoint(federation):
    return _pelican_configuration(federation)["director_endpoint"]


def _parse_federation(path, federation):
    if federation is None:
        # try and get federation name from URL, e.g. osdf://
        parsed = parse_url(path)
        if parsed.scheme:
            federation = parsed.scheme
            path = parsed.path
        else:
            # otherwise use the default federation
            federation = DEFAULT_FEDERATION
    try:
        return path, KNOWN_FEDERATIONS[federation.lower()]
    except KeyError:
        return path, (federation or DEFAULT_FEDERATION).lower()


def get_urls(path, federation=None, random=False):
    path, federation = _parse_federation(path, federation)

    # get URL of director
    director = _pelican_director_endpoint(federation)

    # make URL for namespace path
    url = make_url(director, path)

    # query and catch redirect
    resp = requests.get(url, allow_redirects=False)
    resp.raise_for_status()
    if resp.status_code < 300 or resp.status_code >= 400:
        raise RuntimeError("invalid response from director: {resp.text}")

    # parse links
    links = resp.headers["link"].split(",")
    if random:
        shuffle(links)
    else:
        links.sort(key=lambda x: int(re.search(r"pri=(\d+)", x).groups()[0]))
    urls = []
    for link in links:
        urls.append(link.split(";", 1)[0].strip("<> "))

    return urls


def get(
    path,
    attempts=3,
    federation=None,
    token=None,
    timeout=10,
    random_cache=False,
    session=None,
    **kwargs,
):
    """GET an object from a Pelican federation using HTTP(S).
    """
    if token is not None:  # construct Authorization header for request
        if isinstance(token, SciToken):
            token = token.serialize().decode("utf-8")
        if isfile(token):
            with open(token, "r") as file:
                token = file.read().strip()
        auth = f"Bearer {token}"
        kwargs.setdefault("headers", {}).setdefault("Authorization", auth)

    if session is None:
        # just use the module-level functions
        session = requests

    # loop over URLs from director
    for i, url in enumerate(get_urls(
        path,
        federation=federation,
        random=random_cache,
    )):
        try:
            resp = session.get(url, timeout=timeout, **kwargs)
            resp.raise_for_status()
        except requests.RequestException as exc:
            # keep going a few times
            warnings.warn(str(exc))
            if attempts and i > attempts:
                break
            continue
        return resp

    raise ValueError(f"failed to get '{path}' from {federation} federation")
