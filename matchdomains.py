from __future__ import print_function
import whois
import Levenshtein
import os
from confusables import unconfuse
from ipwhois.net import Net
from ipwhois.asn import IPASN
import math
import tldextract
from tld import get_tld
import re
import concurrent.futures
import dns.resolver
import pprint
import time
import datetime
import yaml

triggerwords_yaml = os.path.dirname(os.path.realpath(__file__)) + '/triggerwords.yaml'

SCORES = {}
TLDS = []
try:
    with open(triggerwords_yaml, 'r') as f:
        config = yaml.safe_load(f)
        # pprint.pprint(config)
    for key, value in config['keywords'].items():
        SCORES[key] = value
    for key, value in config['static'].items():
        SCORES[key] = value
    TLDS = config[tlds]
except:
    pass

class MatchedDomain:
    """
    An object for holding each matched domain. We can store all of the pertinent data related to this particular domain
    here.
    Attributes
    ----------
    domain: str
    match: str
    dns_records: dict
    asn_records: dict
    whois_records: dict
    subdomains: list
    score: int
    shannon_entropy: float
    levenshtein_ratio:
    levenshtein_distance
    IPs: list

    Methods
    -------
    enrich()
 """
    domain: str = ""
    match: str = ""
    dns_records: dict = {}
    asn_records: dict = {}
    whois_records: dict = {}
    subdomains: list = []
    shannon_entropy: float = 0.0
    levenshtein_ratio: float = 0.0
    levenshtein_distance: float = 0.0
    score: int = 0
    IPs: list = []

    def __init__(self, domain, match):
        self.domain = domain
        self.match = match

    def __diff_dates(self, date1, date2):
        return abs((date2 - date1).days)

    def __repr__(self):
        return repr((self.domain,  self.score, self.match, self.shannon_entropy, self.levenshtein_ratio, self.levenshtein_distance))

    def enrich(self):
        # each of the internal methods that gets more data. there is a set sequence on these
        # self.__get_dns_data()
        # pprint.pprint((self.dns_records))
        # self.__get_ip2cidr()
        # pprint.pprint((self.asn_records))
        # self.__get_whois()  this is too slow. we need to find a reason to run who_is
        # pprint.pprint(self.whois_records)  # not working ???
        # let's see which score high enough to look into
        score = 0
        for t in TLDS:
            if self.domain.endswith(t):
                score += 20
        # Removing TLD to catch inner TLD in subdomain (ie. passportoffice.gov.uk-otherdomain.com)
        try:
            res = get_tld(self.domain, as_object=True, fail_silently=True, fix_protocol=True)
            domain_without_outer_tld = '.'.join([res.subdomain, res.domain])
        except Exception:
            domain_without_outer_tld = ""
            pass

        self.__get_entropy()
        # TODO this is a lazy calculation. Should we should base it on actual entropy?
        score += int(round(self.shannon_entropy * 10))

        # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
        unconfused_domain_without_tld = unconfuse(domain_without_outer_tld)
        #print(f"domain:{self.domain},innertld:{domain_without_outer_tld},unconfuse:{unconfused_domain_without_tld}")
        # at this point we've stripped off the outer TLD and unconfused the domain.
        words_in_domain = re.split("\W+", unconfused_domain_without_tld)

        # look for fake, hidden .coms ie. govuk.com-account-management.info
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

        # score the word based on triggerwords.yaml
        for word in SCORES:
            if word in unconfused_domain_without_tld:
                score += SCORES[word]
        #================
        # TODO calculate score based on lev
        # do we even need this check, since we're not using the output below....
        self.__get_levenshtein()

        # TODO- figure out
        # compare the domain against the strong match words
        # aka hmrc, taxrefund, dvla
        for key in [k for (k,s) in SCORES.items() if s >= 70]:
            # this isn't going to be effecticve for overly generic words like 'email'
            for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                #LOG.info(f"word:{word}")
                #LOG.info(f"key:{key}")
                if Levenshtein.distance(str(word), str(key)) == 1:
                    score += 70

        # Lots of hyphens '-'
        if 'xn--' not in self.domain and self.domain.count('-') >= 4:
            score += self.domain.count('-') * 3

        # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
        if self.domain.count('.') >= 3:
            score += self.domain.count('.') * 3

        self.score = score
        #print(
        #    f"domain:{self.domain},score:{score},matched on:{self.match},entropy:{self.shannon_entropy},levenshtein ratio:{self.levenshtein_ratio},Levenshtein distance:{self.levenshtein_distance}")

        # we need to decide how to filter this list.
        # many won't be malicious


        """ Lev
            when we want to analyse these... 
            > 0.8 : Red?
            > 0.4 : Amber?
            <0.4 : green?
        """
        """
            shannon
            >4:     red
            3.5-4:  amber
        """
        # malicious TLD - add 20
        #     # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
        """
        try:
            res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
            domain = '.'.join([res.subdomain, res.domain])
        except Exception:
            pass
        """
        #   score += int(round(entropy.shannon_entropy(domain)*50))

    def __get_levenshtein(self):
        ext_domain = tldextract.extract(self.domain)
        LevWord1 = ext_domain.domain  # domain name
        LevWord2 = self.match  # the trigger word it matched on

        """ when we want to analyse these... 
            > 0.8 : Red?
            > 0.4 : Amber?
            <0.4 : green?
        """
        self.levenshtein_ratio = Levenshtein.ratio(LevWord1, LevWord2)
        self.levenshtein_distance = Levenshtein.distance(LevWord1, LevWord2)

    def __get_dns_data(self):
        """
        get the DNS records for this domain
        """
        MX = []
        NS = []
        A = []
        AAAA = []
        SOA = []
        CNAME = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1

        rrtypes = ['A', 'MX', 'NS', 'AAAA', 'SOA']
        for r in rrtypes:
            try:
                answer = resolver.query(self.domain, r)
                for answer in answer:
                    if r == 'A':
                        A.append(answer.address)
                        self.dns_records.update({r: A})
                    if r == 'MX':
                        MX.append(answer.exchange.to_text()[:-1])
                        self.dns_records.update({r: MX})
                    if r == 'NS':
                        NS.append(answer.target.to_text()[:-1])
                        self.dns_records.update({r: NS})
                    if r == 'AAAA':
                        AAAA.append(answer.address)
                        self.dns_records.update({r: AAAA})
                    if r == 'SOA':
                        SOA.append(answer.mname.to_text()[:-1])
                        self.dns_records.update({r: SOA})
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.name.EmptyLabel:
                pass
            except dns.resolver.NoNameservers:
                pass
            except dns.resolver.Timeout:
                pass
            except dns.exception.DNSException:
                pass

        # let's grab the IPs too. maybe these will get moved
        for k, v in self.dns_records.items():
            for ip in v:
                aa = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
                if aa:
                    self.IPs.append(ip)

    def __ip2cidr_lookup(self, ip):
        try:
            net = Net(ip)
            return IPASN(net).lookup()
        except:
            LOG.warning(f"ip2cidr exception {sys.exc_info()[0]}")

    def __get_ip2cidr(self):
        if len(self.IPs) > 0:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.IPs)) as executor:
                future_to_ip2cidr = {executor.submit(self.__ip2cidr_lookup, ip): ip for ip in self.IPs}
                for future in concurrent.futures.as_completed(future_to_ip2cidr):
                    ipaddress = future_to_ip2cidr[future]
                    data = future.result()
                    self.asn_records[ipaddress] = data.items()

    def __get_whois(self):

        hack = False
        try:
            try:
                whois_res = whois.query(self.domain)
            except (whois.exceptions.UnknownTld, whois.exceptions.WhoisCommandFailed) as e:
                LOG.warning(f"{e} for {self.domain}")
                # this whois library only supports a small handfull of TLDs...
                # TODO look at swapping out with another whois library
                hack = True
            name = whois_res.name
        except:
            if not hack:
                name = ""
            else:
                name = "Unsupported TLD"
        try:
            creation_date = whois_res.creation_date
        except:
            creation_date = ""
        try:
            emails = whois_res.emails
        except:
            emails = ""
        try:
            registrar = whois_res.registrar
        except:
            registrar = ""
        try:
            updated_date = whois_res.updated_date
        except:
            updated_date = ""
        try:
            expiration_date = whois_res.expiration_date
        except:
            expiration_date = ""

        current_date = datetime.datetime.now()
        if isinstance(creation_date, datetime.datetime) or isinstance(expiration_date,
                                                                      datetime.datetime) or isinstance(updated_date,
                                                                                                       datetime.datetime):
            res = self.__diff_dates(current_date, creation_date)

            self.whois_records = {"creation_date": creation_date, \
                                  "creation_date_diff": res, \
                                  "emails": emails, \
                                  "name": name, \
                                  "registrar": registrar, \
                                  "updated_date": updated_date, \
                                  "expiration_date": expiration_date}

        elif isinstance(creation_date, list) or isinstance(expiration_date, list) or isinstance(updated_date, list):
            creation_date = whois_res.creation_date[0]
            updated_date = whois_res.updated_date[0]
            expiration_date = whois_res.expiration_date[0]
            res = self.__diff_dates(current_date, creation_date)

            self.whois_records = {"creation_date": creation_date, \
                                  "creation_date_diff": res, \
                                  "emails": emails, \
                                  "name": name, \
                                  "registrar": registrar, \
                                  "updated_date": updated_date, \
                                  "expiration_date": expiration_date}

            time.sleep(1)

    def __get_entropy(self):
        """attempt at implementing a shannons entropy count"""

        str_list = list(self.domain)
        alphabet = list(set(self.domain))
        frequecy = []
        for symbol in alphabet:
            count = 0
            for sym in str_list:
                if sym == symbol:
                    count += 1
            frequecy.append(float(count) / len(str_list))

        entropy_score = 0.0
        for f in frequecy:
            entropy_score += f * math.log(f, 2)
        entropy_score = -entropy_score
        self.shannon_entropy = entropy_score
