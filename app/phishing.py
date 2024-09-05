from urllib.parse import urlparse, urlencode
import requests
from datetime import datetime
import urllib.request
import urllib
from bs4 import BeautifulSoup
import re
import ipaddress
import pickle
from enum import Enum
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from typing import Optional
from pandas import DataFrame
import whois
import pandas as pd
from urllib.parse import urlparse, unquote
import re
from collections import Counter
from bs4 import BeautifulSoup
from requests import Response
from sklearn.model_selection import train_test_split


class DomainProperty(dict):
    def __init__(self, domain) -> None:
        self.URLLength = domain.get('URLLength')
        self.DomainLength = domain.get('DomainLength')
        self.IsDomainIP = domain.get('IsDomainIP')
        self.TLDIndex = domain.get('TLDIndex')
        self.URLSimilarityIndex = domain.get('URLSimilarityIndex')
        self.CharContinuationRate = domain.get('CharContinuationRate')
        self.TLDLegitimateProb = domain.get('TLDLegitimateProb')
        self.URLCharProb = domain.get('URLCharProb')
        self.TLDLength = domain.get('TLDLength')
        self.NoOfSubDomain = domain.get('NoOfSubDomain')
        self.HasObfuscation = domain.get('HasObfuscation')
        self.NoOfObfuscatedChar = domain.get('NoOfObfuscatedChar')
        self.NoOfLettersInURL = domain.get('NoOfLettersInURL')
        self.NoOfDegitsInURL = domain.get('NoOfDegitsInURL')
        self.NoOfEqualsInURL = domain.get('NoOfEqualsInURL')
        self.NoOfQMarkInURL = domain.get('NoOfQMarkInURL')
        self.NoOfAmpersandInURL = domain.get('NoOfAmpersandInURL')
        self.IsHTTPS = domain.get('IsHTTPS')


class HtmlProperty(dict):
    def __init__(self, html) -> None:
        self.LargestLineLength = html.get('LargestLineLength')
        self.HasTitle = html.get('HasTitle')
        self.URLTitleMatchScore = html.get('URLTitleMatchScore')
        self.HasFavicon = html.get('HasFavicon')
        self.NoOfURLRedirect = html.get('NoOfURLRedirect')
        self.NoOfiFrame = html.get('NoOfiFrame')
        self.HasHiddenFields = html.get('HasHiddenFields')


class Properties(dict):
    def __init__(self, properties: dict) -> None:
        self.domain = DomainProperty(properties.get('domain', {}))
        self.html = HtmlProperty(properties.get('html', {}))


class Domain(object):
    def __init__(self, url: str, properties: dict) -> None:
        self.url = url
        self.properties = Properties(properties)


class PhishingType(str, Enum):
    NONE = 'NONE'
    DOMAIN = 'DOMAIN'
    HTML_JS = 'HTML & JS'


forest_domain: Optional[RandomForestClassifier] = None
forest_html: Optional[RandomForestClassifier] = None
tld: DataFrame = DataFrame()
frequency_distribution: DataFrame = DataFrame()
tld_mapping: dict = {}
top10mil: DataFrame = DataFrame()


def load_models():
    global forest_domain, forest_html, tld, frequency_distribution, tld_mapping, top10mil
    forest_domain = pickle.load(
        open("models/sitedata/forest_domain.pkl", "rb"))
    forest_html = pickle.load(open("models/sitedata/forest_html.pkl", "rb"))
    tld = pd.read_csv("models/sitedata/data/tld.csv")
    top10mil = pd.read_csv("models/sitedata/data/top10milliondomains.csv")
    frequency_distribution = pd.read_csv("models/sitedata/data/frequency.csv")
    tld_mapping = {tld: idx for idx, tld in enumerate(tld['TLD'])}


def prepare_domain(body: dict) -> Domain | None:
    if not body or "url" not in body:
        return None

    domain_body = Domain(body.get('url'), body.get("properties", {}))

    if not domain_body.properties.domain:
        domain_body.properties.domain = domain(domain_body.url)
    if not domain_body.properties.html:
        domain_body.properties.html = html(domain_body.url)
    return domain_body


def domain(url: str) -> DomainProperty:
    domain_str = get_domain(url)
    url_sim_index = float(top10mil['Domain'].head(1_000_000).apply(
        lambda row: get_url_similarity_index(get_domain(url), row)).max())
    try:
        tld_index = tld_mapping[get_tld(domain_str)]
    except Exception as _:
        tld_index = -1
    domain_property = {
        'URLLength': len(url),
        'DomainLength': get_domain_length(domain_str),
        'IsDomainIP': is_domain_ip(domain_str),
        'TLDIndex': tld_index,
        'URLSimilarityIndex': url_sim_index,
        'CharContinuationRate': char_continuation_rate(domain_str),
        'TLDLegitimateProb': get_tld_legitimate_prob(domain_str),
        'URLCharProb': get_url_char_frequency(domain_str),
        'TLDLength': get_tld_length(domain_str),
        'NoOfSubDomain': get_num_of_sub_domains(domain_str),
        'HasObfuscation': has_obfuscation(url),
        'NoOfObfuscatedChar': num_of_obsufcation(url),
        'NoOfLettersInURL': num_of_letters(url),
        'NoOfDegitsInURL': num_of_digits(url),
        'NoOfEqualsInURL': num_of_equal(url),
        'NoOfQMarkInURL': num_of_qmark(url),
        'NoOfAmpersandInURL': num_of_amp(url),
        'IsHTTPS': is_https(url),
    }
    print(domain_property)
    return DomainProperty(domain_property)


def html(url: str) -> HtmlProperty:
    try:
        response = requests.get(url)
    except Exception as _:
        response = ""
    html_properties = {
        'LargestLineLength': longest_line_of_code(response.text),
        'HasTitle': has_title(response.text),
        'URLTitleMatchScore': get_title_url_match_score(url, get_title(response.text)),
        'HasFavicon': has_favicon(response.text),
        'NoOfURLRedirect': number_of_redirects(response),
        'NoOfiFrame': num_of_iframe(response.text),
        'HasHiddenFields': has_hidden_fields(response.text),
    }
    return HtmlProperty(html_properties)


def is_phishing(domain: Domain) -> PhishingType:
    domain_data = np.fromiter(
        domain.properties.domain.__dict__.values(), dtype=int).reshape(1, -1)
    result = forest_domain.predict(domain_data)[0]
    if result == 0:
        return PhishingType.DOMAIN
    html_data = np.fromiter(
        domain.properties.html.__dict__.values(), dtype=float).reshape(1, -1)
    result = forest_html.predict(html_data)[0]
    if result == 0:
        return PhishingType.HTML_JS
    return PhishingType.NONE


def url_length(url: str) -> int:
    return len(url) - 1


def get_domain(url: str) -> str:
    return urlparse(url).netloc


def get_domain_length(domain: str) -> int:
    return len(domain)


def is_domain_ip(domain: str) -> bool:
    if not domain.split('.')[-1].isalpha():
        return 0
    return 1


def get_tld(domain: str) -> str:
    return domain.split('.')[-1]


def get_url_similarity_index(src: str, tar: str) -> int:
    # X = shortest url, Y = longest url, n = length of shorttest from src to tar
    X, Y, n = get_min(src, tar)
    length_of_longest_url = max(len(src), len(tar))
    similarity_index = 0
    base_value = 50 / length_of_longest_url
    sum_of_natural_numbers = (
        length_of_longest_url * (length_of_longest_url + 1)) / 2
    for i in range(0, n):
        if X[i] == Y[i]:
            similarity_index = similarity_index + base_value + \
                (50 * (length_of_longest_url - i)) / sum_of_natural_numbers
            if similarity_index == 100:
                return similarity_index
        else:
            # remove ith (unmatched) character from longest url
            Y = Y[:i] + Y[i + 1:]
            # Set X = shortest, Y = longest, and n = length of shortest url
            X, Y, n = get_min(src, tar)
            i = i - 1
    return similarity_index


def get_min(src: str, tar: str) -> tuple[str, str, int]:
    return min([src, tar], key=len), max([src, tar], key=len), min(len(src), len(tar))

# 1. remove the tld
# 2. get longest sequence of alphabet
# 3. get longest sequence of special chars
# 4. get longest sequence of numbers
# 5. devide by length


def char_continuation_rate(domain: str) -> float:
    domain_check = ".".join(domain.split('.')[:len(domain.split('.')) - 1])
    abc_check = r"[^\d|\!\@\#\$\%\^\&\*\(\)\{\}\|\\\+\-\=\_\\\/\.\,]+"
    number_check = r"\d+"
    special_check = r"[\!\@\#\$\%\^\&\*\(\)\{\}\|\\\+\-\=\_\\\/\.\,]+"
    abc_regex = re.compile(abc_check)
    number_regex = re.compile(number_check)
    special_regex = re.compile(special_check)
    max_abc = max(abc_regex.findall(domain_check), key=len, default="")
    max_number = max(number_regex.findall(domain_check), key=len, default="")
    max_special = max(special_regex.findall(domain_check), key=len, default="")
    return (len(max_abc) + len(max_number) + len(max_special)) / len(domain_check)


def get_tld_legitimate_prob(domain):
    tld_result = get_tld(domain)
    try:
        return float(tld[tld['TLD'] == tld_result]['Ratio'].values[0])
    except Exception as _:
        return 0


def get_url_char_frequency(domain: str) -> float:
    freq = 0
    for letter in domain:
        freq += float(frequency_distribution[frequency_distribution['Letter']
                      == letter]['Frequency'].values[0] / len(domain))
    return freq


def get_tld_length(domain):
    return len(get_tld(domain))


def get_num_of_sub_domains(domain):
    return len(domain.split(".")) - 2


def levenshtein_distance(s1, s2):
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(
                    1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]


def num_of_obsufcation(url):
    return levenshtein_distance(unquote(url), url) / 3


def has_obfuscation(url):
    if num_of_obsufcation(url) > 0:
        return 1
    return 0


def is_https(url):
    if urlparse(url).scheme != 'https':
        return 0
    return 1


def num_of_letters(url):
    return len("".join(re.findall(r"[^0-9|\!\@\#\$\%\^\&\*\(\)\{\}\|\\\+\-\=\_\\\/\.\,]+", url)))


def num_of_digits(url):
    return len("".join(re.findall(r'\d+', url)))


def num_of_equal(url):
    return len("".join(re.findall(r'=+', url)))


def num_of_qmark(url):
    return len("".join(re.findall(r'\?+', url)))


def num_of_amp(url):
    return len("".join(re.findall(r'\&+', url)))


def longest_line_of_code(html):
    return len(max(html.split('\n'), key=len))


def has_favicon(html):
    soup = BeautifulSoup(html, features="html.parser")
    icon = soup.find("link", rel="shortcut icon")
    if not icon:
        return 0
    return 1


def has_title(html):
    soup = BeautifulSoup(html, features="html.parser")
    title = soup.find("title")
    if not title:
        return 0
    return 1


def get_title(html):
    soup = BeautifulSoup(html, features="html.parser")
    title = soup.find("title")
    if not title:
        return ""
    return title.string


def number_of_redirects(response):
    return len(response.history)


def num_of_iframe(html):
    soup = BeautifulSoup(html, features="html.parser")
    iframe = soup.find_all("iframe")
    return len(iframe)


def has_hidden_fields(html):
    soup = BeautifulSoup(html, features="html.parser")
    hidden_tags = soup.find_all("input", type="hidden")
    if not hidden_tags:
        return 0
    return 1


def get_title_url_match_score(url: str, title: str) -> float:
    t_set = title.split()
    domain = get_domain(url)
    domain_check = ".".join(domain.split('.')[:len(domain.split('.')) - 1])
    score = 0
    base_score = 100 / len(domain_check)
    for element in t_set:
        if domain_check.find(element) >= 0:
            n = len(element)
            score += base_score * n
            domain_check = domain_check.replace(element, "")
            if score > 99.9:
                score = 100
    return score
