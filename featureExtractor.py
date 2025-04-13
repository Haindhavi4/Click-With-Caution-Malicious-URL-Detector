import whois
from urllib.parse import urlparse
import httpx
import pickle as pk
import pandas as pd
import extractorFunctions as ef

# Function to extract features
def featureExtraction(url):
    features = []

    # Address bar based features
    features.append(ef.getLength(url))
    features.append(ef.getDepth(url))
    features.append(ef.tinyURL(url))
    features.append(ef.prefixSuffix(url))
    features.append(ef.no_of_dots(url))
    features.append(ef.sensitive_word(url))

    # Domain-based features
    dns = 0  # Default: Not phishing
    domain_name = None
    
    try:
        parsed_netloc = urlparse(url).netloc.strip()
        if parsed_netloc:
            domain_name = whois.whois(parsed_netloc)
        else:
            raise ValueError("Invalid domain")
    except (whois.parser.PywhoisError, ValueError):
        dns = 1  # If WHOIS lookup fails, assume phishing
        domain_name = None
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        dns = 1
        domain_name = None

    features.append(1 if dns == 1 else ef.domainAge(domain_name))
    features.append(1 if dns == 1 else ef.domainEnd(domain_name))

    # HTML & Javascript based features
    dom_features = []
    
    try:
        response = httpx.get(url, timeout=5)  # Added timeout
        dom_features.append(ef.iframe(response))
        dom_features.append(ef.mouseOver(response))
        dom_features.append(ef.forwarding(response))
    except httpx.RequestError as e:
        print(f"HTTP Request failed: {e}")
        dom_features.extend([1, 1, 1])  # Assume phishing if request fails

    # Additional URL-based features
    features.append(ef.has_unicode(url))
    features.append(ef.haveAtSign(url))
    features.append(ef.havingIP(url))

    # Load PCA model
    try:
        with open('model/pca_model.pkl', 'rb') as file:
            pca = pk.load(file)

        # Convert DOM features into DataFrame for PCA transformation
        dom_df = pd.DataFrame([dom_features], columns=['iFrame', 'Web_Forwards', 'Mouse_Over'])
        transformed_feature = pca.transform(dom_df)[0][0]
        features.append(transformed_feature)
    except Exception as e:
        print(f"PCA Transformation Error: {e}")
        features.append(0)  # Default value if PCA transformation fails

    # Define final feature names
    feature_names = [
        'URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix', 'No_Of_Dots', 'Sensitive_Words',
        'Domain_Age', 'Domain_End', 'Has_Unicode', 'Have_At_Sign', 'Have_IP', 'domain_att'
    ]

    # Convert features into DataFrame
    feature_row = pd.DataFrame([features], columns=feature_names)

    return feature_row