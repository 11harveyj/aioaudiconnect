from abc import abstractmethod, ABCMeta
import json
import uuid
import base64
import os
import math
import re
import logging
from time import strftime, gmtime
from datetime import timedelta, datetime

from .models import (
    TripDataResponse,
    CurrentVehicleDataResponse,
    VehicleDataResponse,
    VehiclesResponse,
    Vehicle,
)
from .audi_api import AudiAPI
from .audi_browserloginresponse import BrowserLoginResponse
from .util import to_byte_array, get_attr

from hashlib import sha256, sha512
import hmac
import asyncio

from urllib.parse import urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup
from requests import RequestException

from typing import Dict

from .params import(
    PARAM_MAX_RESPONSE_ATTEMPTS,
    PARAM_REQUEST_STATUS_SLEEP,
    PARAM_HTTP_API_BASE_URL,
    PARAM_HTTP_MARKETS_CONFIG,
    PARAM_HTTP_MARKETS_DYN_CONFIG,
    PARAM_HDR_XAPP_VERSION,
    PARAM_HDR_USER_AGENT,
    PARAM_OPENID_CONFIG,
    PARAM_OPENID_AUTHORIZATION_BASEURL,
    PARAM_OPENID_CLIENTID,
    PARAM_OPENID_MBBOAUTH_BASEURL,
    PARAM_OPENID_AUTHORIZATION_ENDPOINT,
    PARAM_OPENID_REVOCATION_ENDPOINT,
    PARAM_OPENID_TOKEN_ENDPOINT,
)

SUCCEEDED = "succeeded"
FAILED = "failed"
REQUEST_SUCCESSFUL = "request_successful"
REQUEST_FAILED = "request_failed"

_LOGGER = logging.getLogger(__name__)

class AudiService:
    def __init__(self, api: AudiAPI, country: str, spin: str) -> None:
        self._api = api
        self._country = country
        self._language = None
        self._type = "Audi"
        self._spin = spin
        self._homeRegion = {}
        self._homeRegionSetter = {}
        self.mbbOAuthBaseURL = None
        self.mbboauthToken = None
        self.xclientId = None
        self._tokenEndpoint = ""
        self._bearer_token_json = None
        self._client_id = ""
        self._authorizationServerBaseURLLive = ""

        if self._country is None:
            self._country = "DE"

    def get_hidden_html_input_form_data(self, response, form_data: dict[str,str]):
        # Now parse the html body and extract the target url, csrf token and other required parameters
        html = BeautifulSoup(response, "html.parser")

        form_inputs = html.find_all("input", attrs={"type": "hidden"})
        for form_input in form_inputs:
            name = form_input.get("name")
            form_data[name] = form_input.get("value")

        return form_data

    def get_post_url(self, response, url):
        # Now parse the html body and extract the target url, csrf token and other required parameters
        html = BeautifulSoup(response, "html.parser")
        form_tag = html.find("form")

        # Extract the target url
        action = form_tag.get("action")
        if action.startswith("http"):
            # Absolute url
            username_post_url = action
        elif action.startswith("/"):
            # Relative to domain
            username_post_url = BrowserLoginResponse.to_absolute(url, action)
        else:
            raise RequestException("Unknown form action: " + action)
        return username_post_url

    async def check_request_successful(
        self, url: str, action: str, successCode: str, failedCode: str, path: str
    ):
        for _ in range(PARAM_MAX_RESPONSE_ATTEMPTS):
            await asyncio.sleep(PARAM_REQUEST_STATUS_SLEEP)

            self._api.set_token(self.vwToken)
            res = await self._api.get(url)

            status = get_attr(res, path)

            if status is None or (failedCode is not None and status == failedCode):
                raise Exception(
                    f"Cannot {action}, return code '{status}'"
                )

            if status == successCode:
                return

    ## Define X_QMAuth Functions
    def _calculate_X_QMAuth(self) -> str:
        # Calcualte X-QMAuth value
        gmtime_100sec = int(
            (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() / 100
        )
        xqmauth_secret = bytes([26,256-74,256-103,37,256-84,23,256-102,256-86,78,256-125,256-85,256-26,113,256-87,71,109,23,100,24,256-72,91,256-41,6,256-15,67,108,256-95,91,256-26,71,256-104,256-100])
        xqmauth_val = hmac.new(
            xqmauth_secret,
            str(gmtime_100sec).encode("ascii", "ignore"),
            digestmod="sha256",
        ).hexdigest()

        #v1:01da27b0:fbdb6e4ba3109bc68040cb83f380796f4d3bb178a626c4cc7e166815b806e4b5
        return "v1:01da27b0:" + xqmauth_val

    ## Define Refresh functions, returns True when refresh was required and successful
    async def refresh_token(self, elapsed_sec: int) -> bool:
        if (self.mbboauthToken is None) or ("refresh_token" not in self.mbboauthToken) or ("expires_in" not in self.mbboauthToken):
            return False

        if (elapsed_sec + 5 * 60) < self.mbboauthToken["expires_in"]:
            # Refresh not required
            return False

        try:
            self.vwToken = await self.mbboauth_refresh()

            # TR/2022-02-10: If a new refresh_token is provided, save it for further refreshes
            if "refresh_token" in self.vwToken:
                self.mbboauthToken["refresh_token"] = self.vwToken["refresh_token"]

            # hdr
            headers = {
               "Accept": "application/json",
               "Accept-Charset": "utf-8",
               "X-QMAuth": self._calculate_X_QMAuth(),
               "User-Agent": PARAM_HDR_USER_AGENT,
               "Content-Type": "application/x-www-form-urlencoded",
            }
            # IDK token request data
            tokenreq_data = {
               "client_id": self._client_id,
               "grant_type": "refresh_token",
               "refresh_token": self._bearer_token_json.get("refresh_token"),
               "response_type": "token id_token",
            }
            # IDK token request
            encoded_tokenreq_data = urlencode(tokenreq_data, encoding="utf-8").replace("+","%20")
            bearer_token_rsp, bearer_token_rsptxt = await self._api.request(
               "POST",
               self._tokenEndpoint,
               encoded_tokenreq_data,
               headers=headers,
               allow_redirects=False,
               rsp_wtxt=True,
            )
            self._bearer_token_json = json.loads(bearer_token_rsptxt)

            # AZS token
            headers = {
               "Accept": "application/json",
               "Accept-Charset": "utf-8",
               "X-App-Version": PARAM_HDR_XAPP_VERSION,
               "X-App-Name": "myAudi",
               "User-Agent": PARAM_HDR_USER_AGENT,
               "Content-Type": "application/json; charset=utf-8",
            }
            asz_req_data = {
               "token": self._bearer_token_json["access_token"],
               "grant_type": "id_token",
               "stage": "live",
               "config": "myaudi",
            }
            azs_token_rsp, azs_token_rsptxt = await self._api.request(
               "POST",
               self._authorizationServerBaseURLLive + "/token",
               json.dumps(asz_req_data),
               headers=headers,
               allow_redirects=False,
               rsp_wtxt=True,
            )
            azs_token_json = json.loads(azs_token_rsptxt)
            self.audiToken = azs_token_json

            return True
        
        except Exception as exception:
            _LOGGER.error("Refresh token failed: " + str(exception))
            return False

    ## Define Login functions
    async def login(self, user: str, password: str):
        await self.login_request(user, password)

    async def login_request(self, user: str, password: str):
        self._api.use_token(None)
        self._api.set_xclient_id(None)
        self.xclientId = None

        markets_json = await self.get_markets()

        if self._country.upper() not in markets_json["countries"]["countrySpecifications"]:
            raise Exception(f"Country {self._country.upper()} not found.")

        self._language = markets_json["countries"]["countrySpecifications"][self._country.upper()]["defaultLanguage"]

        marketcfg_json = await self.get_dynamic_market_config()

        # Use dynamic config from market config
        self._client_id = PARAM_OPENID_CLIENTID
        if "idkClientIDAndroidLive" in marketcfg_json:
            self._client_id = marketcfg_json["idkClientIDAndroidLive"]
        
        self._authorizationServerBaseURLLive = PARAM_OPENID_AUTHORIZATION_BASEURL
        if "mbbOAuthBaseURLLive" in marketcfg_json:
            self.mbbOAuthBaseURL = marketcfg_json["mbbOAuthBaseURLLive"]

        # get openid config
        openidcfg_json = await self.get_openid_config()

        # use dynamic config from openId config
        authorization_endpoint = PARAM_OPENID_AUTHORIZATION_ENDPOINT
        if "authorization_endpoint" in openidcfg_json:
            authorization_endpoint = openidcfg_json["authorization_endpoint"]
        self._tokenEndpoint = PARAM_OPENID_TOKEN_ENDPOINT
        if "token_endpoint" in openidcfg_json:
            self._tokenEndpoint = openidcfg_json["token_endpoint"]
        revocation_endpoint = PARAM_OPENID_REVOCATION_ENDPOINT
        if revocation_endpoint in openidcfg_json:
            revocation_endpoint = openidcfg_json["revocation_endpoint"]

        self.vwToken = await self.login_page(authorization_endpoint, user, password)

    async def login_page(self, auth_endpoint: str, email: str, password: str) -> object:
        # generate code_challenge
        code_verifier = str(base64.urlsafe_b64encode(os.urandom(32)), "utf-8").strip(
            "="
        )
        code_challenge = str(
            base64.urlsafe_b64encode(
                sha256(code_verifier.encode("ascii", "ignore")).digest()
            ),
            "utf-8",
        ).strip("=")
        code_challenge_method = "S256"

        #
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())

        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "X-App-Version": PARAM_HDR_XAPP_VERSION,
            "X-App-Name": "myAudi",
            "User-Agent": PARAM_HDR_USER_AGENT,
        }
        idk_data = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": "myaudi:///",
            "scope": "address profile badge birthdate birthplace nationalIdentifier nationality profession email vin phone nickname name picture mbb gallery openid",
            "state": state,
            "nonce": nonce,
            "prompt": "login",
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "ui_locales": "de-de de",
        }
        idk_rsp, idk_rsptxt = await self._api.send_request(
            method="GET",
            url=auth_endpoint,
            body=None,
            headers=headers,
            params=idk_data,
            rsp_wtxt=True
        )

        # form_data with just email address
        submit_data = self.get_hidden_html_input_form_data(idk_rsptxt, {"email": email})
        submit_url = self.get_post_url(idk_rsptxt, auth_endpoint)
        # send request with email address
        email_rsp, email_rsptxt = await self._api.send_request(
            method="POST",
            url=submit_url,
            body=submit_data,
            headers=headers,
            cookies=idk_rsp.cookies,
            allow_redirects=True,
            rsp_wtxt=True
        )

        # form_data with password
        # 2022-01-29: new HTML response uses a js two build the html form data + button.
        #             Therefore it's not possible to extract hmac and other form data. 
        #             --> extract hmac from embedded js snippet.
        regex_res = re.findall('"hmac"\s*:\s*"[0-9a-fA-F]+"', email_rsptxt)
        if regex_res:
           submit_url = submit_url.replace("identifier", "authenticate")
           submit_data["hmac"] = regex_res[0].split(":")[1].strip('"')
           submit_data["password"] = password
        else:
           submit_data = self.get_hidden_html_input_form_data(email_rsptxt, {"password": password})
           submit_url = self.get_post_url(email_rsptxt, submit_url)

        # send password
        pw_rsp, pw_rsptxt = await self._api.send_request(
            method="POST",
            url=submit_url,
            body=submit_data,
            headers=headers,
            cookies=idk_rsp.cookies,
            allow_redirects=False,
            rsp_wtxt=True,
        )

        # forward1 after pwd
        fwd1_rsp, fwd1_rsptxt = await self._api.send_request(
            method="GET",
            url=pw_rsp.headers["Location"],
            body=None,
            headers=headers,
            cookies=idk_rsp.cookies,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        # forward2 after pwd
        fwd2_rsp, fwd2_rsptxt = await self._api.send_request(
            method="GET",
            url=fwd1_rsp.headers["Location"],
            body=None,
            headers=headers,
            cookies=idk_rsp.cookies,
            allow_redirects=False,
            rsp_wtxt=True,
        )

        # get tokens
        codeauth_rsp, codeauth_rsptxt = await self._api.send_request(
            method="GET",
            url=fwd2_rsp.headers["Location"],
            body=None,
            headers=headers,
            cookies=fwd2_rsp.cookies,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        authcode_parsed = urlparse(
            codeauth_rsp.headers["Location"][len("myaudi:///?") :]
        )
        authcode_strings = parse_qs(authcode_parsed.path)

        # hdr
        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "X-QMAuth": self._calculate_X_QMAuth(),
            "User-Agent": PARAM_HDR_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        # IDK token request data
        tokenreq_data = {
            "client_id": self._client_id,
            "grant_type": "authorization_code",
            "code": authcode_strings["code"][0],
            "redirect_uri": "myaudi:///",
            "response_type": "token id_token",
            "code_verifier": code_verifier,
        }

        # IDK token request
        encoded_tokenreq_data = urlencode(tokenreq_data, encoding="utf-8").replace("+","%20")
        bearer_token_rsp, bearer_token_rsptxt = await self._api.send_request(
            method="POST",
            url=self._tokenEndpoint,
            body=encoded_tokenreq_data,
            headers=headers,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        self._bearer_token_json = json.loads(bearer_token_rsptxt)

        # AZS token
        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "X-App-Version": PARAM_HDR_XAPP_VERSION,
            "X-App-Name": "myAudi",
            "User-Agent": PARAM_HDR_USER_AGENT,
            "Content-Type": "application/json; charset=utf-8",
        }
        asz_req_data = {
            "token": self._bearer_token_json["access_token"],
            "grant_type": "id_token",
            "stage": "live",
            "config": "myaudi",
        }
        azs_token_rsp, azs_token_rsptxt = await self._api.send_request(
            method="POST",
            url=PARAM_OPENID_AUTHORIZATION_BASEURL + "/token",
            body=json.dumps(asz_req_data),
            headers=headers,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        azs_token_json = json.loads(azs_token_rsptxt)
        self.audiToken = azs_token_json

        # mbboauth client register
        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "User-Agent": PARAM_HDR_USER_AGENT,
            "Content-Type": "application/json; charset=utf-8",
        }
        mbboauth_reg_data = {
            "client_name": "Pixel4",
            "platform": "google",
            "client_brand": "Audi",
            "appName": "myAudi",
            "appVersion": PARAM_HDR_XAPP_VERSION,
            "appId": "de.myaudi.mobile.assistant",
        }
        mbboauth_client_reg_rsp, mbboauth_client_reg_rsptxt = await self._api.send_request(
            method="POST",
            url=self.mbbOAuthBaseURL + "/mobile/register/v1",
            body=json.dumps(mbboauth_reg_data),
            headers=headers,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        mbboauth_client_reg_json = json.loads(mbboauth_client_reg_rsptxt)
        self.xclientId = mbboauth_client_reg_json["client_id"]
        self._api.set_xclient_id(self.xclientId)

        # mbboauth auth
        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "User-Agent": PARAM_HDR_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Client-ID": self.xclientId,
        }
        mbboauth_auth_data = {
            "grant_type": "id_token",
            "token": self._bearer_token_json["id_token"],
            "scope": "sc2:fal",
        }
        encoded_mbboauth_auth_data = urlencode(mbboauth_auth_data, encoding="utf-8").replace("+","%20")
        mbboauth_auth_rsp, mbboauth_auth_rsptxt = await self._api.send_request(
            method="POST",
            url=self.mbbOAuthBaseURL + "/mobile/oauth2/v1/token",
            body=encoded_mbboauth_auth_data,
            headers=headers,
            allow_redirects=False,
            rsp_wtxt=True,
        )
        mbboauth_auth_json = json.loads(mbboauth_auth_rsptxt)
        # store token and expiration time
        self.mbboauthToken = mbboauth_auth_json

        # mbboauth refresh (app immediately refreshes the token)
        return await self.mbboauth_refresh(mbboauth_client_reg_rsp.cookies)

    async def mbboauth_refresh(self, cookies: object=None) -> object:
        headers = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "User-Agent": PARAM_HDR_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Client-ID": self.xclientId,
        }
        mbboauth_refresh_data = {
            "grant_type": "refresh_token",
            "token": self.mbboauthToken["refresh_token"],
            "scope": "sc2:fal",
            # "vin": vin,  << App uses a dedicated VIN here, but it works without, don't know
        }
        encoded_mbboauth_refresh_data = urlencode(mbboauth_refresh_data, encoding="utf-8").replace("+","%20")
        mbboauth_refresh_rsp, mbboauth_refresh_rsptxt = await self._api.send_request(
            method="POST",
            url=self.mbbOAuthBaseURL + "/mobile/oauth2/v1/token",
            body=encoded_mbboauth_refresh_data,
            headers=headers,
            allow_redirects=False,
            cookies=cookies,
            rsp_wtxt=True,
        )

        return json.loads(mbboauth_refresh_rsptxt)

    def _generate_security_pin_hash(self, challenge):
        pin = to_byte_array(self._spin)
        byteChallenge = to_byte_array(challenge)
        b = bytes(pin + byteChallenge)
        return sha512(b).hexdigest().upper()

    async def get_dynamic_market_config(self):
        url = PARAM_HTTP_MARKETS_DYN_CONFIG.format(
            c=self._country,
            l=self._language,
            v=PARAM_HDR_XAPP_VERSION
        )

        return await self._api.send_request(method="GET", url=url, body=None)

    async def get_openid_config(self):
        url = PARAM_OPENID_CONFIG.format(
            "na" if self._country.upper() is "US" else "emea"
        )

        return await self._api.send_request(method="GET", url=url, body=None)

    async def get_markets(self):
        return await self._api.send_request(
            method="GET",
            url=PARAM_HTTP_MARKETS_CONFIG,
            body=None
        )