import pickle
from enum import Enum
from sklearn.neural_network import MLPClassifier
import numpy as np


class DomainProperty(object):
    def __init__(self, domain) -> None:
        self.is_ip_address = domain['is_ip_address']
        self.have_at_sign = domain['have_at_sign']
        self.is_long_url = domain['is_long_url']
        self.redirection = domain['redirection']
        self.is_http = domain['is_http']
        self.is_shortened = domain['is_shortened']
        self.is_using_prefix = domain['is_using_prefix']


class DnsProperty(object):
    def __init__(self, dns) -> None:
        self.is_in_dns = dns['is_in_dns']
        self.is_top_100k = dns['is_top_100k']
        self.is_domain_new = dns['is_domain_new']
        self.is_domain_about_to_expire = dns['is_domain_about_to_expire']


class HtmlProperty(object):
    def __init__(self, html) -> None:
        self.is_empty_iframe = html['is_empty_iframe']
        self.is_fake_status_bar = html['is_fake_status_bar']
        self.is_disabled_right_click = html['is_disabled_right_click']
        self.redirect_count = html['redirect_count']


class Properties(object):
    def __init__(self, properties: dict) -> None:
        self.domain = DomainProperty(properties['domain'])
        self.dns = DnsProperty(properties['dns'])
        self.html = HtmlProperty(properties['html'])


class Domain(object):
    def __init__(self, url: str, properties: dict) -> None:
        self.url = url
        self.properties = Properties(properties)


class PhishingType(str, Enum):
    NONE = 'NONE'
    DOMAIN = 'DOMAIN'
    DNS = 'DNS'
    HTML_JS = 'HTML & JS'


mlp_domain: MLPClassifier = None
mlp_dns: MLPClassifier = None
mlp_html: MLPClassifier = None


def load_models():
    global mlp_domain, mlp_dns, mlp_html
    mlp_domain = pickle.load(open("models/sitedata/mlp_domain.pkl", "rb"))
    mlp_dns = pickle.load(open("models/sitedata/mlp_dns.pkl", "rb"))
    mlp_html = pickle.load(open("models/sitedata/mlp_html_js.pkl", "rb"))


def prepare_domain(body: object) -> Domain | None:
    if not body or "url" not in body:
        return None

    domain_body = Domain(body['url'], body['properties'])

    if not domain_body.properties:
        domain_body.properties = {}
    if not domain_body.properties.domain:
        domain_body.properties.domain = domain(domain_body.url)
    if not domain_body.properties.dns:
        domain_body.properties.dns = dns(domain_body.url)
    if not domain_body.properties.html:
        domain_body.properties.html = html(domain_body.url)

    print(domain_body.properties.domain)
    return domain_body


def domain(url: str) -> DomainProperty:
    pass


def dns(url: str) -> DnsProperty:
    pass


def html(url: str) -> HtmlProperty:
    pass


def is_phishing(domain: Domain) -> PhishingType:
    domain_data = np.fromiter(
        domain.properties.domain.__dict__.values(), dtype=int).reshape(1, -1)
    result = mlp_domain.predict(domain_data)[0]
    if result == 1:
        return PhishingType.DOMAIN
    dns_data = np.fromiter(
        domain.properties.dns.__dict__.values(), dtype=int).reshape(1, -1)
    result = mlp_dns.predict(dns_data)[0]
    if result == 1:
        return PhishingType.DNS
    html_data = np.fromiter(
        domain.properties.html.__dict__.values(), dtype=int).reshape(1, -1)
    result = mlp_html.predict(html_data)[0]
    if result == 1:
        return PhishingType.HTML_JS
    return PhishingType.NONE
