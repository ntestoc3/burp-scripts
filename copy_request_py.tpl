[% if common-code %]
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### proxy setting
proxy = 'http://127.0.0.1:8080'
use_proxy = False

MY_PROXY = None
if use_proxy:
    MY_PROXY = {
        'http': proxy,
        'https': proxy,
    }

common_http_args = {"verify": False,
                    "proxies": MY_PROXY, }

http = requests.session()
[% endif %]
[% safe %][% for info in items %]
brup[{info.id}]_url = "[{info.url}]"[% if info.cookies|not-empty %]
burp[{info.id}]_cookies = {[% for c in info.cookies %]
    "[{c.k}]": "[{c.v}]",[% endfor %]
    }[% endif %]
burp[{info.id}]_headers = {[% for hdr in info.headers %]
    "[{hdr.k|name}]": "[{hdr.v}]",[% endfor %]
    }[% if info.body|not-empty %][% if info.content-type = "application/json" %]
burp[{info.id}]_json =[{info.body|json}]
[% elif info.content-type = "application/x-www-form-urlencoded" %]
burp[{info.id}]_data = [{info.body|json}]
[% else %]
burp[{info.id}]_data = "[{info.body}]"[% endif %][% endif %]
burp[{info.id}] = http.request("[{info.method|name|upper}]", brup[{info.id}]_url, headers=burp[{info.id}]_headers, [% if info.body|not-empty %][% if info.content-type = "application/json" %]json=burp[{info.id}]_json, [% else %]data=burp[{info.id}]_data, [% endif %][% endif %][% if info.cookies|not-empty %]cookies=burp[{info.id}]_cookies, [% endif %]**common_http_args)
[% endfor %][% endsafe %]
