import re
from urllib.parse import urlparse, urljoin
import ssl
import socket
import whois
from bs4 import BeautifulSoup
import requests
from datetime import datetime
import dns.resolver
import joblib
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

def having_ip_address(url):
    ip_pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if ip_pattern.fullmatch(url):
        return -1
    else:
        return 1

def url_length_feature(url):
    url_length = len(url)
    if url_length < 54:
        return -1
    elif 54 <= url_length <= 75:
        return 0
    else:
        return 1
    
def shortining_service(url):
    short_url_domains = [
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'mcaf.ee', 
        'adf.ly', 'bit.do', 'bc.vc', 'shorturl.at', 'shorte.st', 'clk.im', 'urlz.fr', 'q.gs',
        'linkbun.ch', 'db.tt', 'qr.ae', 'v.gd', 'tiny.cc', 'tr.im', 'clck.ru', 'x.co', 
        'youtu.be', 'cutt.ly', 'rebrand.ly', 't.ly', 'bl.ink', '1url.com', 'lnkd.in', 'vzturl.com',
        'po.st', 'scrnch.me', 'gg.gg', 'dft.ba', 'flic.kr', 'snipurl.com', 'clic.ly', 'budurl.com',
        'fb.me', 'bitly.com', 't2mio.com', 'url.ie', 'zi.ma', 'safelinking.net', 'qr.net', 
        'adcraft.co', 's2r.co', 'surl.co.uk', 'smsh.me', 'shorl.com', 'chilp.it', 'prettylinkpro.com',
        'adfoc.us', 'kl.am', 'wp.me', 'sh.st', 'soo.gd', 'surl.li', 'zws.im', 'ht.ly', 'url9.de',
        'we.tc', 'lt.tl', 'adfa.st', 'aka.ms', 'hyperurl.co', 'mzl.la', 'cutt.us', 'durl.me',
        'go2l.ink', 'tweetburner.com', 'safe.mn'
    ]
    
    pattern = re.compile(r'\b(' + '|'.join(re.escape(domain) for domain in short_url_domains) + r')\b', re.IGNORECASE)
    
    if pattern.search(url):
        return -1
    else:
        return 1
    
def having_at_symbol(url):
    return -1 if '@' in url else 1

def double_slash_redirecting(url):
    parsed_url = urlparse(url)
    return -1 if '//' in url.split(parsed_url.scheme + '://', 1)[-1] else 1

def prefix_suffix(url):
    parsed_url = urlparse(url)
    return 1 if '-' in parsed_url.netloc else -1

def having_sub_domain(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    num_dots = len(domain_parts) - 1

    if num_dots < 3:
        return -1
    elif num_dots == 3:
        return 0
    else:
        return 1
def check_ssl_certificate(domain):
    """
    Verilen domain için SSL sertifikasının geçerli olup olmadığını kontrol eder.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                return True
    except Exception:
        return False

def sslfinal_state(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        return -1
    
    domain = parsed_url.netloc
    if check_ssl_certificate(domain):
        return 1 
    else:
        return 0
    
def domain_registration_length(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

        if creation_date and expiration_date and (expiration_date - creation_date).days > 365:
            return 1
        else:
            return -1
    except Exception:
        return -1
    
def favicon_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            icon_link = soup.find("link", rel="shortcut icon")
            if not icon_link:
                icon_link = soup.find("link", rel="icon")
            if icon_link:
                icon_url = icon_link.get('href')
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                icon_url = urljoin(base_url, icon_url)
                if urlparse(icon_url).netloc == parsed_url.netloc:
                    return 1
                else:
                    return -1
        return -1
    except Exception:
        return -1

def port_feature(url):
    parsed_url = urlparse(url)
    if parsed_url.port:
        return 1
    else:
        return -1
    
def https_token_feature(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if 'https' in domain:
        return -1
    else:
        return 1
def request_url_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            tags = soup.find_all(['img', 'script', 'link'])
            same_domain_count = 0
            total_count = 0

            for tag in tags:
                src = tag.get('src') or tag.get('href')
                if src:
                    total_count += 1
                    full_url = urljoin(url, src)
                    if urlparse(full_url).netloc == base_domain:
                        same_domain_count += 1

            if total_count == 0:
                return 1
            if same_domain_count / total_count >= 0.5:
                return 1
            else:
                return -1
        return -1
    except Exception:
        return -1

def url_of_anchor_feature(url):
    """
    Sayfadaki <a> taglarının href attributelerinin ana domain ile aynı domain'den olup olmadığını kontrol eder.
    Eğer linklerin çoğu ana domain ile aynı yerden geliyorsa 1, değilse -1 döner.
    """
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            anchor_tags = soup.find_all('a')
            same_domain_count = 0
            total_count = 0

            for tag in anchor_tags:
                href = tag.get('href')
                if href and not href.startswith('#'):
                    total_count += 1
                    full_url = urljoin(url, href)
                    if urlparse(full_url).netloc == base_domain:
                        same_domain_count += 1

            if total_count == 0:
                return 1
            if same_domain_count / total_count >= 0.5:
                return 1
            else:
                return -1
        return -1
    except Exception:
        return -1
    
def links_in_tags_feature(url):
    """
    Sayfadaki <meta>, <script> ve <link> taglarının url attributelerinin ana domain ile aynı domain'den olup olmadığını kontrol eder.
    Eğer linklerin çoğu ana domain ile aynı yerden geliyorsa 1, değilse -1 döner.
    """
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            tags = soup.find_all(['meta', 'script', 'link'])
            same_domain_count = 0
            total_count = 0

            for tag in tags:
                if tag.name == 'meta':
                    src = tag.get('content')
                elif tag.name == 'script':
                    src = tag.get('src')
                elif tag.name == 'link':
                    src = tag.get('href')
                else:
                    src = None
                
                if src:
                    total_count += 1
                    full_url = urljoin(url, src)
                    if urlparse(full_url).netloc == base_domain:
                        same_domain_count += 1

            if total_count == 0:
                return 1
            if same_domain_count / total_count >= 0.5:
                return 1
            else:
                return -1
        return -1
    except Exception:
        return -1
    
def sfh_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc

            forms = soup.find_all('form')
            if not forms:
                return 1

            for form in forms:
                action = form.get('action')
                if not action or action.strip() == "":
                    return -1
                full_url = urljoin(url, action)
                if urlparse(full_url).netloc != base_domain:
                    return 0

            return 1
        return -1
    except Exception:
        return -1
    
def submitting_to_email_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')
            if not forms:
                return 1

            for form in forms:
                action = form.get('action')
                if action and 'mailto:' in action:
                    return -1

            return 1
        return -1
    except Exception:
        return -1
    
def abnormal_url_feature(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    if domain in path:
        return -1
    else:
        return 1

def redirect_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if len(response.history) > 1:
            return -1
        else:
            return 1
    except Exception:
        return -1
    
def on_mouseover_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            anchor_tags = soup.find_all('a')

            for tag in anchor_tags:
                if 'onmouseover' in tag.attrs:
                    return -1

            return 1
        return -1
    except Exception:
        return -1
    
def right_click_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            body_tag = soup.find('body')

            if body_tag and 'oncontextmenu' in body_tag.attrs:
                return -1

            return 1
        return -1
    except Exception:
        return -1

def popupwindow_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            script_tags = soup.find_all('script')

            for tag in script_tags:
                if tag.string and 'window.open' in tag.string:
                    return -1

            return 1
        return -1
    except Exception:
        return -1
    
def iframe_feature(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            iframes = soup.find_all('iframe')

            if iframes:
                return -1
            else:
                return 1
        return -1
    except Exception:
        return -1
    
def age_of_domain_feature(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime):
            age_in_days = (datetime.now() - creation_date).days
            if age_in_days > 6 * 30:
                return 1
            else:
                return -1
        return -1
    except Exception:
        return -1
    
def dnsrecord_feature(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return 1
        else:
            return -1
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return -1
    except Exception:
        return -1

def google_index_feature(url):
    try:
        query = f"site:{url}"
        google_search_url = f"https://www.google.com/search?q={query}"
        response = requests.get(google_search_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            if "ile ilgili hiçbir arama sonucu mevcut değil" in soup.text:
                return -1
            else:
                return 1
        return -1
    except Exception:
        return -1
    
def links_pointing_to_page(url):
    try:
        query = f"link:{url}"
        google_search_url = f"https://www.google.com/search?q={query}"
        response = requests.get(google_search_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            if "ile ilgili hiçbir arama sonucu mevcut değil" in soup.text:
                return -1
            else:
                return 1
        return -1
    except Exception:
        return -1
def statistical_report_feature(url):
    try:
        query = f'phishing report for {url}'
        google_search_url = f'https://www.google.com/search?q={query}'
        response = requests.get(google_search_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            if 'ile ilgili hiçbir arama sonucu mevcut değil' or 'Eksik' in soup.text:
                return 1
            else:
                return -1
        return 1
    except Exception as e:
        print(f"Bir hata oluştu: {e}")
        return 1
def extract_features(url):
    features = {}
    
    features['having_ip_address'] = having_ip_address(url)
    features['url_length'] = url_length_feature(url)
    features['shortining_service'] = shortining_service(url)    
    features['having_at_symbol'] = having_at_symbol(url)    
    features['double_slash_redirecting'] = double_slash_redirecting(url)    
    features['prefix_suffix'] = prefix_suffix(url)   
    features['having_sub_domain'] = having_sub_domain(url)
    features['sslfinal_state'] = sslfinal_state(url)
    features['domain_registration_length'] = domain_registration_length(url)
    features['favicon'] = favicon_feature(url)
    features['port'] = favicon_feature(url)
    features['https_token'] = https_token_feature(url)
    features['request_url'] = request_url_feature(url)
    features['url_of_anchor'] = url_of_anchor_feature(url)
    features['links_in_tags'] = links_in_tags_feature(url)
    features['sfh'] = sfh_feature(url)
    features['submitting_to_email'] = submitting_to_email_feature(url)
    features['abnormal_url'] = abnormal_url_feature(url)
    features['redirect'] = redirect_feature(url)
    features['on_mouseover'] = on_mouseover_feature(url)
    features['rightclick'] = right_click_feature(url)
    features['popupwindow'] = popupwindow_feature(url)
    features['iframe'] = iframe_feature(url)
    features['age_of_domain'] = age_of_domain_feature(url)
    features['dnsrecord'] = dnsrecord_feature(url)
    features['google_index'] = google_index_feature(url)
    features['links_pointing_to_page'] = links_in_tags_feature(url)    
    features['statistical_report'] = statistical_report_feature(url)


    return features

stacking_model = joblib.load("C:/Users/Selito/Desktop/Project/Machine Learning Models/Stacking Model (Ensemble Method)/Stacking_Model.joblib")
scaler = joblib.load("C:/Users/Selito/Desktop/Project/Machine Learning Models/Stacking Model (Ensemble Method)/Scaler.pkl")

sample_url = input("Please enter the URL you want to check: ")
features = extract_features(sample_url)
print(features)

features_df = pd.DataFrame([features])

features_scaled = scaler.transform(features_df)

prediction = stacking_model.predict(features_scaled)
prediction_proba = stacking_model.predict_proba(features_scaled)


if prediction[0] == 1:
    print(f"Predict: Legitimate")
else:
    print(f"Predict: Phishing")

print(f"Predict Probability: {prediction_proba[0]}")