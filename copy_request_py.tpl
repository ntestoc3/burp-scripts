{% if common_code -%}
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
{% endif %}
{%- for info in items %}
burp{{ info.id }}_url = "{{ info.url }}"
  {%- if info.cookies %}
burp{{ info.id }}_cookies = {
                 {%- for c in info.cookies -%}
                    {{ c.k }}: {{ c.v }},
                 {% endfor %}}
  {%- endif %}
burp{{ info.id }}_headers = {
                 {%- for hdr in info.headers -%}
                   "{{ hdr[0]|http_header }}": {{ hdr[1] }},
                 {% endfor %}}
  {%- if info.body %}
    {%- if info.content_type == "application/json" %}
burp{{ info.id }}_json = {{ info.body|json }}
    {%- elif info.content_type == "application/x-www-form-urlencoded" %}
burp{{ info.id }}_data = {{ info.body|json }}
    {%- else %}
burp{{ info.id }}_data = "{{ info.body }}"
    {%- endif %}
  {%- endif %}
burp{{ info.id }} = http.request("{{ info.method|name|upper }}", burp{{ info.id }}_url, headers=burp{{ info.id }}_headers,
  {%- if info.body %}
    {%- if info.content_type == "application/json" %} json=burp{{ info.id }}_json,
    {%- else %} data=burp{{ info.id }}_data,
    {%- endif %}
  {%- endif %}
  {%- if info.cookies %} cookies=burp{{info.id}}_cookies,
  {%- endif %} **common_http_args)
{% endfor %}
