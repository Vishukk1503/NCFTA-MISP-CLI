"""Shared read-only PyMISP client with verified TLS and no redirects."""
from contextlib import contextmanager
import logging
from urllib.parse import urlsplit

from pymisp import PyMISP
from pymisp.exceptions import PyMISPError
import requests


class NCFTAClientError(Exception):
    """Sanitized connection error safe for terminal output."""


class ReadOnlyAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, origin):
        super().__init__()
        self.origin = origin

    def send(self, request, **kwargs):
        url = urlsplit(request.url)
        origin = (url.scheme, url.netloc)
        if origin != self.origin:
            raise NCFTAClientError('Request to another server refused.')
        if request.method != 'GET' and not (
                request.method == 'POST' and url.path.rstrip('/') == '/events/restSearch'):
            raise NCFTAClientError('Operation refused by the read-only client.')
        if not kwargs.get('verify', True):
            raise NCFTAClientError('TLS certificate verification must remain enabled.')
        response = super().send(request, **kwargs)
        if 300 <= response.status_code < 400:
            response.close()
            raise NCFTAClientError('Redirect refused. Check the server endpoint.')
        if response.status_code >= 400:
            status = response.status_code
            response.close()
            raise NCFTAClientError(f'MISP request failed: HTTP {status}. Check permissions and server availability.')
        return response


@contextmanager
def connect(url, key, timeout, ca_bundle=None):
    # PyMISP may log response bodies and headers. Keep those out of CLI logs.
    logger = logging.getLogger('pymisp')
    previous_disabled = logger.disabled
    logger.disabled = True
    parsed = urlsplit(url)
    adapter = ReadOnlyAdapter((parsed.scheme, parsed.netloc))
    try:
        client = PyMISP(url, key, ssl=str(ca_bundle) if ca_bundle else True,
                        timeout=timeout, debug=False, https_adapter=adapter,
                        tool='NCFTA-ReadOnly-CLI')
        yield client
    except NCFTAClientError:
        raise
    except requests.exceptions.SSLError:
        raise NCFTAClientError('TLS verification failed. Supply a trusted --ca-bundle if required.') from None
    except (PyMISPError, requests.exceptions.RequestException):
        raise NCFTAClientError('PyMISP connection or API request failed. Check key, API permissions, VPN, CA bundle and server compatibility.') from None
    finally:
        adapter.close()
        logger.disabled = previous_disabled

