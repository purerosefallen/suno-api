import os
import time
from http.cookies import SimpleCookie
import datetime
import requests

from utils import COMMON_HEADERS, notify, logger


class SunoCookie:
    def __init__(self):
        self.cookie = SimpleCookie()
        self.session_id = None
        self.token = None
        self.expire_at = None
        self.email = None
        self.phonenumber = None

    def load_cookie(self, cookie_str):
        self.cookie.load(cookie_str)

    def get_cookie(self):
        return ";".join([f"{i}={self.cookie.get(i).value}" for i in self.cookie.keys()])

    def set_session_id(self, session_id):
        self.session_id = session_id

    def get_session_id(self):
        return self.session_id

    def get_token(self):
        return self.token

    def set_token(self, token: str):
        self.token = token

    def set_expire_at(self, expire_at: int):
        self.expire_at = expire_at

    def get_expire_at(self):
        return self.expire_at

    def set_email(self, email: str):
        self.email = email

    def get_email(self):
        return self.email
    
    def set_phonenumber(self, phonenumber: str):
        self.phonenumber = phonenumber
    
    def get_phonenumber(self):
        return self.phonenumber
    
    def get_login_identifier(self):
        if self.email:
            return self.email
        if self.phonenumber:
            return self.phonenumber


clerk_js_version = "5.35.1"
CLERK_BASE_URL = (
    f"https://clerk.suno.com/v1/client?_clerk_js_version={clerk_js_version}"
)
suno_auth = SunoCookie()
suno_auth.load_cookie(os.getenv("COOKIE"))


def fetch_session_id(suno_cookie: SunoCookie):
    headers = {"cookie": suno_cookie.get_cookie()}
    headers.update(COMMON_HEADERS)
    resp = requests.get(CLERK_BASE_URL, headers=headers, timeout=5)
    session_id = resp.json().get("response").get("last_active_session_id")
    expire_at = resp.json().get("response").get("sessions")[0]["expire_at"]
    user_data = resp.json().get("response").get("sessions")[0]["user"]

    email = None
    if user_data.get("primary_email_address_id"):
        email = user_data.get("email_addresses")[0].get("email_address")
        email = f"{email.split('@')[0][:5]}****@{email.split('@')[1]}"
        suno_cookie.set_email(email)
    
    phonenumber = None
    if user_data.get("primary_phone_number_id"):
        phonenumber = user_data.get("phone_numbers")[0].get("phone_number")
        suno_cookie.set_phonenumber(phonenumber)
    
    suno_cookie.set_session_id(session_id)
    suno_cookie.set_expire_at(expire_at)

    logger.info(
        f"{suno_cookie.get_login_identifier()} suno cookie will expire at {datetime.datetime.fromtimestamp(expire_at/1000).strftime('%Y-%m-%d %H:%M:%S')} session_id -> {session_id}"
    )


fetch_session_id(suno_auth)


def update_token(suno_cookie: SunoCookie):
    headers = {"cookie": suno_cookie.get_cookie()}
    headers.update(COMMON_HEADERS)

    url = f"https://clerk.suno.com/v1/client?__clerk_api_version=2021-02-05&_clerk_js_version={clerk_js_version}&_method=PATCH"
    resp = requests.post(
        url=url,
        headers=headers,
        timeout=5,
    )

    resp_headers = dict(resp.headers)
    set_cookie = resp_headers.get("Set-Cookie")
    suno_cookie.load_cookie(set_cookie)
    token = resp.json()["sessions"][0]["last_active_token"]["jwt"]
    if not token:
        logger.error(f"update token failed, response -> {resp.json()}")
        return
    suno_cookie.set_token(token)


def keep_alive(suno_cookie: SunoCookie):
    interval = suno_cookie.get_expire_at() - int(time.time() * 1000)
    if interval < 0:
        notify(
            f"login: {suno_cookie.get_login_identifier()} suno cookie has expired at {datetime.datetime.fromtimestamp(suno_cookie.get_expire_at()/1000).strftime('%Y-%m-%d %H:%M:%S')}, please update"
        )
    elif interval < 60 * 60 * 24 * 1000:
        notify(
            f"login: {suno_cookie.get_login_identifier()} suno cookie will expire at {datetime.datetime.fromtimestamp(suno_cookie.get_expire_at()/1000).strftime('%Y-%m-%d %H:%M:%S')}, please update"
        )
    try:
        update_token(suno_cookie)
    except Exception as e:
        logger.error(
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} *** keep_alive error -> {e} ***"
        )
