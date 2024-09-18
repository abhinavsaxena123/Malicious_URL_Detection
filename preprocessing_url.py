from urllib.parse import urlparse
import re
from tld import get_tld
 
def get_url_length(url):
    return len(str(url))


def having_ip_address(url):
    match = re.search(
        r'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        r'([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        r'((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    
    if match:
        return 1
    else:
        return 0


def count_https(url):
    return url.count('https')


def count_http(url):
    return url.count('http')


def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:      
        return 1      #(indicating the URL is abnormal)
    else:
        return 0     #(indicating the URL is normal)
    


def calculate_count(url, feature_list):
    counts = {char: url.count(char) for char in feature_list}
    return counts

feature_list = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']


def sum_count_special_characters(url: str) -> int:
    special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//']

    num_special_chars = sum(char in special_chars for char in url)
    return num_special_chars


def redirection(url):
  pos = url.rfind('//') # Find the last occurrence of '//' in the URL
  if pos > 6:
    if pos > 7:
      return 1    # Return 1 indicating that the URL is suspicious
    else:
      return 0    # Return 0 indicating that the URL is not suspicious
  else:
    return 0   # Return 0 indicating that the URL is not suspicious
  

def shortening_service(url):
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      r'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1    #illegitimate
    else:
        return 0     #legitimate



def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits += 1
    return digits


def hostname_length(url):
    return len(urlparse(url).netloc)


import tldextract
def get_top_level_domain(url):
    extracted = tldextract.extract(url)
    return extracted.suffix

def get_tld_length(url, fail_silently=True):
    try:
        tld = get_top_level_domain(url)
        return len(tld)
    except:
        return -1
    
    
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
    

suspicious_keywords = [
    'paypal', 'login', 'signin', 'bank', 'account', 'update', 'free', 
    'lucky', 'service', 'bonus', 'ebayisapi', 'webscr'
]

def suspicious_words(url):
    # Joining the suspicious keywords into a pattern, making it case-insensitive
    pattern = '|'.join(suspicious_keywords)
    
    # Search for the pattern in the URL (case-insensitive)
    if re.search(pattern, url, re.IGNORECASE):
        return 1
    else:
        return 0
    


