import async_timeout
import json
from datetime import datetime

from asyncio import TimeoutError, CancelledError
from aiohttp import ClientSession, ClientResponseError
from aiohttp.hdrs import METH_GET, METH_POST, METH_PUT

from .params import (
    PARAM_HDR_USER_AGENT,
    PARAM_HDR_XAPP_VERSION,
    PARAM_API_TIMEOUT,
)

class AudiAPI:
    def __init__(self, session, proxy=None):
        self._token = None
        self._xclientid = None
        self._session = session
        if proxy is not None:
            self._proxy = {"http": proxy, "https": proxy}
        else:
            self._proxy = None

    def set_token(self, token: str):
        self._token = token

    def set_xclient_id(self, xclientid: str):
        self._xclientid = xclientid

    async def send_request(
        self,
        method,
        url,
        body,
        headers: dict[str, str] = None,
        raw_reply: bool = False,
        raw_contents: bool = False,
        rsp_wtxt: bool = False,
        **args
    ):
        """Send a HTTP request to an API"""
        try:
            with async_timeout.timeout(PARAM_API_TIMEOUT):
                async with self._session.request(
                    method, url, headers=headers, data=body, **args
                ) as response:
                    if raw_reply:
                        return response
                    if rsp_wtxt:
                        txt = await response.text()
                        return response, txt
                    elif raw_contents:
                        return await response.read()
                    elif response.status == 200 or response.status == 202:
                        return await response.json(loads=json_loads)
                    else:
                        raise Exception("ERROR")

        except CancelledError:
            raise TimeoutError("Web request timed out.")
        except TimeoutError:
            raise TimeoutError("Web request timed out.")
        except Exception:
            raise

    
    async def get(
        self, url, raw_reply: bool = False, raw_contents: bool = False, **kwargs
    ):
        full_headers = self._get_headers()
        r = await self.request(
            METH_GET,
            url,
            data=None,
            headers=full_headers,
            raw_reply=raw_reply,
            raw_contents=raw_contents,
            **kwargs
        )
        return r

    async def put(self, url, data=None, headers: dict[str, str] = None):
        full_headers = self._get_headers()
        if headers is not None:
            full_headers.update(headers)
        r = await self.request(METH_PUT, url, headers=full_headers, data=data)
        return r

    async def post(
        self,
        url,
        data=None,
        headers: dict[str, str] = None,
        use_json: bool = True,
        raw_reply: bool = False,
        raw_contents: bool = False,
        **kwargs
    ):
        full_headers = self._get_headers()
        if headers is not None:
            full_headers.update(headers)
        if use_json and data is not None:
            data = json.dumps(data)
        r = await self.request(
            METH_POST,
            url,
            headers=full_headers,
            data=data,
            raw_reply=raw_reply,
            raw_contents=raw_contents,
            **kwargs
        )
        return r

    def _get_headers(self):
        data = {
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
            "X-App-Version": PARAM_HDR_XAPP_VERSION,
            "X-App-Name": "myAudi",
            "User-Agent": PARAM_HDR_USER_AGENT,
        }
        if self._token != None:
            data["Authorization"] = "Bearer " + self._token
        if self._xclientid != None:
            data["X-Client-ID"] = self._xclientid

        return data

def obj_parser(obj):
    """Parse datetime."""
    for key, val in obj.items():
        try:
            obj[key] = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S%z")
        except (TypeError, ValueError):
            pass
    return obj

def json_loads(s):
    return json.loads(s, object_hook=obj_parser)