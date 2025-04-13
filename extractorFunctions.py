# importing required packages for Address Bar Based feature Extraction
from urllib.parse import urlparse, urlencode, unquote
import re
# importing required packages for Domain Based Feature Extraction
from datetime import datetime


# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ip_pattern, url)
    if match:
        return 1
    return 0

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  return len(url)

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate

def no_of_dots(url):
  return url.count('.')

sensitiveWords = ["account", "confirm", "banking", "secure", "ebyisapi", "webscr", "signin", "mail",
                  "install", "toolbar", "backup", "paypal", "password", "username", "verify", "update",
                  "login", "support", "billing", "transaction", "security", "payment", "verify", "online",
                  "customer", "service", "accountupdate", "verification", "important", "confidential",
                  "limited", "access", "securitycheck", "verifyaccount", "information", "change", "notice"
                  "myaccount", "updateinfo", "loginsecure", "protect", "transaction", "identity", "member"
                  "personal", "actionrequired", "loginverify", "validate", "paymentupdate", "urgent"]

def sensitive_word(url):
  domain = urlparse(url).netloc
  for i in sensitiveWords:
    if i in domain:
      return 1
  return 0


def has_unicode(url):
    try:
        parsed_url = urlparse(url).netloc
        return 1 if parsed_url.encode('idna').decode('utf-8') != parsed_url else 0
    except:
        return 1  # Assume phishing if decoding fails


# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
    if not domain_name or not domain_name.creation_date or not domain_name.expiration_date:
        return 1  # Default to phishing if missing data
    
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Take the first value if it's a list
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = (expiration_date - creation_date).days
        return 1 if (age_days / 30) < 6 else 0  # Phishing if domain age < 6 months
    except:
        return 1

# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

# 15. IFrame Redirection (iFrame)
def iframe(response):
    if not response or not hasattr(response, 'text') or response.text == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1


# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def iframe(response):
    if not response or not hasattr(response, 'text') or response.text == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1