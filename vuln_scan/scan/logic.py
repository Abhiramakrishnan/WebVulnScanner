import re
import requests
from bs4 import BeautifulSoup

def is_valid_url(url):

    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def scan_url(url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL format")
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Request failed: {e}")

    soup = BeautifulSoup(response.content, 'html.parser')

    results = {
        'csrf': check_csrf(soup),
        'sql_injection': check_sql_injection(url),
        'xss': check_xss(url),
        'broken_access_control': check_broken_access_control(url),
    }
    return results


def check_csrf(soup):
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'type': 'hidden', 'name': re.compile('csrf', re.IGNORECASE)}):
            return True
    return False

def check_sql_injection(url):
    payloads = [
        "' OR '1'='1", "' OR '1'='1' --", "' OR ''='",
        '" OR "1"="1', '" OR ""="', '1 OR 1=1',
        "admin' --", "admin' #", "admin'/*",
        "admin' or '1'='1"
    ]
    for payload in payloads:
        try:
            response = requests.get(url, params={'q': payload}, timeout=10)
            if any(error in response.text for error in [
                "You have an error in your SQL syntax", "Warning: mysql_", "Unclosed quotation mark",
                "quoted string not properly terminated", "SQLSTATE[HY000]"
            ]):
                return True
        except requests.exceptions.RequestException as e:
            return {'error': f"Request failed during SQL injection check: {e}"}
    return False

def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "<a href=javascript:alert('XSS')>Click me</a>"
    ]
    for payload in payloads:
        try:
            response = requests.get(url, params={'q': payload}, timeout=10)
            if payload in response.text:
                return True
        except requests.exceptions.RequestException as e:
            return {'error': f"Request failed during XSS check: {e}"}
    return False

def check_broken_access_control(url):
    try:
        response = requests.get(url + '/admin', timeout=10)
        if response.status_code == 200:
            return True
    except requests.exceptions.RequestException as e:
        return {'error': f"Request failed during broken access control check: {e}"}
    return False

