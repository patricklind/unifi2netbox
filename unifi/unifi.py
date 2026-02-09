import json
import logging
import os
import threading
import time
import warnings

import pyotp
import requests
from urllib3.exceptions import InsecureRequestWarning

from .sites import Sites

file_lock = threading.Lock()

# Suppress only the InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

logger = logging.getLogger(__name__)


class Unifi:
    """
    Handles interactions with UniFi API for both:
    - Integration API v1 (API key)
    - Legacy / UniFi OS session login (username/password)
    """

    SESSION_FILE = os.path.expanduser("~/.unifi_session.json")
    DEFAULT_TIMEOUT = 15
    _session_data = {}

    AUTH_MODES = (
        {
            "name": "unifi_os",
            "login_endpoint": "/api/auth/login",
            "api_prefix": "/proxy/network",
        },
        {
            "name": "legacy",
            "login_endpoint": "/api/login",
            "api_prefix": "",
        },
    )

    def __init__(
        self,
        base_url=None,
        username=None,
        password=None,
        mfa_secret=None,
        api_key=None,
        api_key_header=None,
    ):
        logger.debug(f"Initializing UniFi connection to: {base_url}")
        self.base_url = base_url.rstrip("/") if base_url else base_url
        self.username = username
        self.password = password
        self.mfa_secret = mfa_secret
        self.api_key = api_key
        self.api_key_header = api_key_header

        self.session = requests.Session()
        self.session_cookie = None
        self.csrf_token = None
        self.auth_mode = None
        self.api_prefix = ""

        self.api_style = None  # "integration" or "legacy"
        self.integration_api_base = None
        self.integration_auth_headers = {}

        if not self.base_url:
            raise ValueError("Missing required configuration: UniFi base URL")

        logger.debug("Loading session from file")
        self.load_session_from_file()

        # Prefer Integration API when API key is provided.
        if self.api_key and self.configure_integration_api():
            self.api_style = "integration"
            logger.info(
                f"Using UniFi Integration API at {self.integration_api_base}"
            )
        else:
            if self.api_key:
                logger.warning(
                    "UNIFI_API_KEY provided but Integration API could not be validated. "
                    "Falling back to session-based login."
                )

            if not all([self.username, self.password]):
                raise ValueError(
                    "Missing credentials. Provide UNIFI_API_KEY or UNIFI_USERNAME + UNIFI_PASSWORD"
                )

            self.api_style = "legacy"
            logger.debug("Authenticating with UniFi controller via session login")
            self.authenticate()

        logger.debug("Fetching sites from UniFi controller")
        self.sites = self.get_sites()
        logger.debug(f"Initialized UniFi connection with {len(self.sites)} sites")

    def _parse_response_json(self, response):
        """Parse JSON from a response and return None for non-JSON bodies."""
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError):
            return None

    def _build_api_url(self, endpoint):
        """Build URL for legacy APIs (session/cookie auth)."""
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        normalized_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        if self.api_prefix and not normalized_endpoint.startswith(self.api_prefix):
            normalized_endpoint = f"{self.api_prefix}{normalized_endpoint}"
        return f"{self.base_url}{normalized_endpoint}"

    def _build_integration_url(self, endpoint):
        """Build URL for Integration API v1 based on discovered integration base path."""
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint

        normalized = endpoint if endpoint.startswith("/") else f"/{endpoint}"

        # Accept either "/sites" style or "/v1/sites" style.
        if normalized.startswith("/proxy/network/integration/v1"):
            normalized = normalized[len("/proxy/network/integration/v1") :]
        elif normalized.startswith("/integration/v1"):
            normalized = normalized[len("/integration/v1") :]
        elif normalized.startswith("/v1"):
            normalized = normalized[len("/v1") :]

        if not normalized:
            normalized = "/"

        return f"{self.integration_api_base}{normalized}"

    def _get_auth_mode_candidates(self):
        """Prioritize the previously working auth mode to reduce retries."""
        modes = list(self.AUTH_MODES)
        if self.auth_mode:
            modes.sort(key=lambda mode: mode["name"] != self.auth_mode)
        return modes

    def _build_login_payload(self):
        """Build login payload with optional 2FA token."""
        payload = {
            "username": self.username,
            "password": self.password,
        }
        otp = None
        if self.mfa_secret:
            otp = pyotp.TOTP(self.mfa_secret)
            payload["ubic_2fa_token"] = otp.now()
        return payload, otp

    def _wait_for_next_totp(self, otp):
        """Wait for the next TOTP code to avoid immediate retry failures."""
        if not otp:
            return
        time_remaining = otp.interval - (int(time.time()) % otp.interval)
        logger.warning(
            f"Invalid 2FA token detected. Next token available in {time_remaining}s."
        )
        while time_remaining > 0:
            print(f"\rRetrying authentication in {time_remaining} seconds...", end="")
            time.sleep(1)
            time_remaining -= 1
        print("\nRetrying now!")

    def _refresh_session_metadata(self, response=None):
        """Refresh auth metadata from session cookies and response headers."""
        cookie_dict = self.session.cookies.get_dict()
        self.session_cookie = cookie_dict.get("unifises") or cookie_dict.get("TOKEN")
        if response:
            self.csrf_token = (
                response.headers.get("X-CSRF-Token")
                or response.headers.get("x-csrf-token")
                or self.session.cookies.get("csrf_token")
                or self.csrf_token
            )

    def _integration_base_candidates(self):
        if "/integration/v1" in self.base_url:
            return [self.base_url]
        return [
            f"{self.base_url}/proxy/network/integration/v1",
            f"{self.base_url}/integration/v1",
        ]

    def _integration_header_candidates(self):
        if not self.api_key:
            return []

        candidates = []

        if self.api_key_header:
            header = self.api_key_header.strip()
            if header.lower() == "authorization":
                candidates.append({"Authorization": f"Bearer {self.api_key}"})
                candidates.append({"Authorization": f"Token {self.api_key}"})
                candidates.append({"Authorization": self.api_key})
            else:
                candidates.append({header: self.api_key})

        candidates.extend(
            [
                {"X-API-KEY": self.api_key},
                {"X-Api-Key": self.api_key},
                {"Authorization": f"Bearer {self.api_key}"},
                {"Authorization": f"Token {self.api_key}"},
                {"Authorization": self.api_key},
            ]
        )

        unique = []
        seen = set()
        for item in candidates:
            signature = tuple(sorted(item.items()))
            if signature not in seen:
                seen.add(signature)
                unique.append(item)
        return unique

    def configure_integration_api(self):
        """Detect working Integration API base URL + auth header format."""
        if not self.api_key:
            return False

        for base in self._integration_base_candidates():
            for auth_headers in self._integration_header_candidates():
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    **auth_headers,
                }

                # Probe /info first (lightweight endpoint)
                info_url = f"{base}/info"
                try:
                    response = self.session.get(
                        info_url,
                        headers=headers,
                        verify=False,
                        timeout=self.DEFAULT_TIMEOUT,
                    )
                except requests.exceptions.RequestException as err:
                    logger.debug(
                        f"Integration probe failed for {info_url} with headers {list(auth_headers.keys())}: {err}"
                    )
                    continue

                response_data = self._parse_response_json(response)
                if response.status_code < 400 and isinstance(response_data, dict):
                    if response_data.get("applicationVersion"):
                        self.integration_api_base = base
                        self.integration_auth_headers = auth_headers
                        logger.debug(
                            f"Integration API validated via /info at {base} using {list(auth_headers.keys())}"
                        )
                        return True

                # Fallback probe: /sites
                sites_url = f"{base}/sites"
                try:
                    sites_response = self.session.get(
                        sites_url,
                        headers=headers,
                        params={"offset": 0, "limit": 1},
                        verify=False,
                        timeout=self.DEFAULT_TIMEOUT,
                    )
                except requests.exceptions.RequestException:
                    continue

                sites_data = self._parse_response_json(sites_response)
                if sites_response.status_code < 400 and isinstance(sites_data, dict):
                    if isinstance(sites_data.get("data"), list):
                        self.integration_api_base = base
                        self.integration_auth_headers = auth_headers
                        logger.debug(
                            f"Integration API validated via /sites at {base} using {list(auth_headers.keys())}"
                        )
                        return True

        return False

    def save_session_to_file(self):
        """Save session data to file, grouped by base_url."""
        logger.debug(f"Saving session data for {self.base_url}")
        self._session_data[self.base_url] = {
            "cookies": self.session.cookies.get_dict(),
            "csrf_token": self.csrf_token,
            "auth_mode": self.auth_mode,
            "api_prefix": self.api_prefix,
            "api_style": self.api_style,
            "integration_api_base": self.integration_api_base,
            "integration_auth_headers": self.integration_auth_headers,
        }
        with file_lock:
            logger.debug(f"Acquired file lock for {self.SESSION_FILE}")
            with open(self.SESSION_FILE, "w") as f:
                json.dump(self._session_data, f)
            logger.info(f"Session data for {self.base_url} saved to file.")

    def load_session_from_file(self):
        """Load session data from file for the current base_url."""
        logger.debug(f"Checking for session file at {self.SESSION_FILE}")
        if not os.path.exists(self.SESSION_FILE):
            logger.debug("No session file found, will authenticate from scratch")
            return

        try:
            with open(self.SESSION_FILE, "r") as f:
                self._session_data = json.load(f)
        except (json.JSONDecodeError, OSError) as err:
            logger.warning(
                f"Failed to load existing UniFi session cache, ignoring it: {err}"
            )
            self._session_data = {}
            return

        session_info = self._session_data.get(self.base_url)
        if not session_info:
            logger.debug(f"No session data found for {self.base_url}")
            return

        logger.debug(f"Found session data for {self.base_url}")
        cookies = session_info.get("cookies", {})
        if isinstance(cookies, dict):
            self.session.cookies.update(cookies)
        self.csrf_token = session_info.get("csrf_token")
        self.auth_mode = session_info.get("auth_mode")
        self.api_prefix = session_info.get("api_prefix", "")

        cached_style = session_info.get("api_style")
        if cached_style in {"legacy", "integration"}:
            self.api_style = cached_style
        self.integration_api_base = session_info.get("integration_api_base")
        headers = session_info.get("integration_auth_headers")
        if isinstance(headers, dict):
            self.integration_auth_headers = headers

        self._refresh_session_metadata()
        logger.info(f"Loaded session data for {self.base_url} from file.")

    def authenticate(self, retry_count=0, max_retries=3):
        """Log in and prepare an authenticated legacy session."""
        logger.debug(f"Authentication attempt {retry_count + 1}/{max_retries + 1}")
        if retry_count >= max_retries:
            logger.error("Max authentication retries reached. Aborting authentication.")
            raise Exception("Authentication failed after maximum retries.")

        payload, otp = self._build_login_payload()
        auth_errors = []

        for mode in self._get_auth_mode_candidates():
            login_url = f"{self.base_url}{mode['login_endpoint']}"
            logger.debug(f"Trying auth mode '{mode['name']}' via {login_url}")

            try:
                response = self.session.post(
                    login_url,
                    json=payload,
                    verify=False,
                    timeout=self.DEFAULT_TIMEOUT,
                )
            except requests.exceptions.RequestException as err:
                logger.warning(f"Auth mode '{mode['name']}' request failed: {err}")
                auth_errors.append(f"{mode['name']}: request error ({err})")
                continue

            response_data = self._parse_response_json(response) or {}
            meta = response_data.get("meta", {}) if isinstance(response_data, dict) else {}
            msg = meta.get("msg")
            rc = meta.get("rc")
            self._refresh_session_metadata(response)

            if rc == "ok" or (
                response.ok and bool(self.session.cookies.get_dict())
            ):
                self.auth_mode = mode["name"]
                self.api_prefix = mode["api_prefix"]
                self._refresh_session_metadata(response)
                self.save_session_to_file()
                logger.info(
                    f"Logged in successfully using auth mode '{self.auth_mode}'."
                )
                return

            if msg == "api.err.Invalid2FAToken":
                logger.warning("Invalid 2FA token detected.")
                self._wait_for_next_totp(otp)
                return self.authenticate(
                    retry_count=retry_count + 1, max_retries=max_retries
                )

            if msg == "api.err.Invalid":
                logger.error("Login failed: invalid credentials.")
                raise ValueError("UniFi authentication failed: invalid credentials.")

            if response.status_code in (404, 405):
                logger.debug(
                    f"Auth mode '{mode['name']}' unavailable (status {response.status_code})."
                )
                auth_errors.append(
                    f"{mode['name']}: endpoint unavailable ({response.status_code})"
                )
                continue

            auth_errors.append(
                f"{mode['name']}: login failed (status={response.status_code}, msg={msg})"
            )

        logger.error("UniFi authentication failed for all auth modes.")
        raise Exception(
            "Authentication failed. "
            + ("; ".join(auth_errors) if auth_errors else "No auth mode succeeded.")
        )

    def _make_request_legacy(self, endpoint, method="GET", data=None, params=None, retry_count=0, max_retries=3):
        if not self.session.cookies.get_dict():
            logger.info("No valid session cookies present. Authenticating...")
            self.authenticate()

        headers = {"Content-Type": "application/json"}
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token

        url = self._build_api_url(endpoint)
        method_upper = method.upper()
        logger.debug(f"Making legacy {method_upper} request to: {url}")

        request_kwargs = {
            "headers": headers,
            "verify": False,
            "timeout": self.DEFAULT_TIMEOUT,
            "params": params,
        }
        if data is not None and method_upper in {"POST", "PUT", "PATCH"}:
            request_kwargs["json"] = data

        try:
            response = self.session.request(method_upper, url, **request_kwargs)
        except requests.exceptions.RequestException as err:
            logger.error(f"Request exception: {err}")
            logger.debug(f"Request failed: {method_upper} {url}", exc_info=True)
            return None

        logger.debug(f"Response status code: {response.status_code}")

        if response.status_code == 401 and retry_count < max_retries:
            logger.warning("Session expired or unauthorized. Re-authenticating...")
            self.authenticate(retry_count=0, max_retries=max_retries)
            return self._make_request_legacy(
                endpoint,
                method=method_upper,
                data=data,
                params=params,
                retry_count=retry_count + 1,
                max_retries=max_retries,
            )

        response_data = self._parse_response_json(response)
        if response.status_code >= 400:
            if isinstance(response_data, dict):
                logger.error(
                    f"Request failed with {response.status_code}: "
                    f"{response_data.get('meta', {}).get('msg', response_data.get('message', 'unknown error'))}"
                )
                return response_data
            logger.error(
                f"Request failed with {response.status_code} and non-JSON response."
            )
            return {
                "statusCode": response.status_code,
                "message": response.text,
            }

        if response_data is None:
            logger.error("Received non-JSON response from UniFi API.")
            return None

        if isinstance(response_data, dict):
            logger.debug(f"Request successful, response keys: {list(response_data.keys())}")
        return response_data

    def _make_request_integration(self, endpoint, method="GET", data=None, params=None, retry_count=0, max_retries=3):
        if not self.integration_api_base:
            if not self.configure_integration_api():
                logger.error("Integration API is not configured.")
                return {
                    "statusCode": 401,
                    "message": "Integration API not configured",
                }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            **self.integration_auth_headers,
        }

        url = self._build_integration_url(endpoint)
        method_upper = method.upper()
        logger.debug(f"Making integration {method_upper} request to: {url}")

        request_kwargs = {
            "headers": headers,
            "verify": False,
            "timeout": self.DEFAULT_TIMEOUT,
            "params": params,
        }
        if data is not None and method_upper in {"POST", "PUT", "PATCH"}:
            request_kwargs["json"] = data

        try:
            response = self.session.request(method_upper, url, **request_kwargs)
        except requests.exceptions.RequestException as err:
            logger.error(f"Integration request exception: {err}")
            logger.debug(f"Request failed: {method_upper} {url}", exc_info=True)
            return None

        response_data = self._parse_response_json(response)

        if response.status_code == 401 and retry_count < max_retries:
            # Retry header/base detection once in case auth header format changed.
            if self.configure_integration_api():
                return self._make_request_integration(
                    endpoint,
                    method=method_upper,
                    data=data,
                    params=params,
                    retry_count=retry_count + 1,
                    max_retries=max_retries,
                )

        if response.status_code >= 400:
            if isinstance(response_data, dict):
                logger.error(
                    f"Integration request failed with {response.status_code}: "
                    f"{response_data.get('code', response_data.get('message', 'unknown error'))}"
                )
                return response_data
            logger.error(
                f"Integration request failed with {response.status_code} and non-JSON response."
            )
            return {
                "statusCode": response.status_code,
                "message": response.text,
            }

        if response_data is None:
            logger.error("Received non-JSON response from Integration API.")
            return None

        return response_data

    def make_request(self, endpoint, method="GET", data=None, params=None, retry_count=0, max_retries=3):
        """Make an authenticated request to the selected UniFi API style."""
        logger.debug(f"API request ({self.api_style}): {method} {endpoint}")
        if self.api_style == "integration":
            return self._make_request_integration(
                endpoint,
                method=method,
                data=data,
                params=params,
                retry_count=retry_count,
                max_retries=max_retries,
            )
        return self._make_request_legacy(
            endpoint,
            method=method,
            data=data,
            params=params,
            retry_count=retry_count,
            max_retries=max_retries,
        )

    def _get_sites_integration(self):
        """Fetch sites from Integration API (/sites)."""
        offset = 0
        limit = 200
        sites = []

        while True:
            response = self.make_request(
                "/sites",
                "GET",
                params={"offset": offset, "limit": limit},
            )
            if not isinstance(response, dict):
                raise ValueError("No sites found (invalid response shape)")

            data = response.get("data")
            if not isinstance(data, list):
                raise ValueError(
                    f"No sites found (missing data list): {response}"
                )

            sites.extend(data)
            logger.debug(f"Retrieved {len(data)} sites at offset {offset}")

            if not data:
                break

            offset += len(data)
            total_count = response.get("totalCount")
            if isinstance(total_count, int) and offset >= total_count:
                break
            if len(data) < response.get("limit", limit):
                break

        site_dict = {}
        for site in sites:
            site_obj = Sites(self, site)
            key = site.get("name") or site.get("internalReference") or site.get("id")
            if key:
                site_dict[key] = site_obj

        return site_dict

    def _get_sites_legacy(self):
        """Fetch sites from legacy/UniFi OS APIs."""
        response = self.make_request("/api/self/sites", "GET")

        if not response:
            logger.error("No response received when fetching sites")
            raise ValueError("No sites found.")

        logger.debug(f"Sites response meta: {response.get('meta', {})}")
        if response.get("meta", {}).get("rc") == "ok":
            sites = response.get("data", [])
            logger.debug(f"Found {len(sites)} sites on controller")
            site_dict = {site["desc"]: Sites(self, site) for site in sites}
            return site_dict

        error_msg = response.get("meta", {}).get("msg")
        logger.error(f"Failed to get sites: {error_msg}")
        return {}

    def get_sites(self) -> dict:
        """Fetch and return all sites from the selected UniFi API style."""
        logger.debug(f"Fetching sites from UniFi controller at {self.base_url}")
        if self.api_style == "integration":
            return self._get_sites_integration()
        return self._get_sites_legacy()

    def site(self, name):
        """Get a single site by name, internal reference, or API id."""
        site = self.sites.get(name)
        if site:
            return site

        for site_obj in self.sites.values():
            if name in {
                site_obj.name,
                getattr(site_obj, "desc", None),
                getattr(site_obj, "internal_reference", None),
                getattr(site_obj, "api_id", None),
            }:
                return site_obj
        return None

    def __getitem__(self, name):
        """Shortcut for accessing a site."""
        return self.site(name)
