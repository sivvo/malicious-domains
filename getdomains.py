from __future__ import print_function

import argparse
import re
import sys
import yaml
import os
import base64
import requests
import logging
import dns.resolver
import concurrent.futures

from zipfile import ZipFile

LOG = logging.getLogger('getdomains.log')
LOG.setLevel(logging.INFO)
FORMATTER = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr = logging.FileHandler('getdomains.log')
hdlr.setFormatter(FORMATTER)
hdlr.setLevel(logging.INFO)
LOG.addHandler(hdlr)
LOG.addHandler(logging.StreamHandler())

triggerwords_yaml = os.path.dirname(os.path.realpath(__file__)) + '/triggerwords.yaml'


class MatchedDoman:
    """
    An object for holding each matched domain. We can store all of the pertinent data related to this particular domain
    here.
    """
    domain: str = ""
    match: str = ""
    dns_records: list = []
    subdomains: list = []
    shannon_entry: float = 0.0
    levenshtein_ratio: float = 0.0

    def __init__(self, domain, match):
        self.domain = domain
        self.match = match

    def get_domain(self):
        return self.domain


class DomainLookup:
    """
    Initialise the class with a date in the format YYYY-mm-dd
    Methods: processmatches

    """
    triggers: dict = {}
    searchdomains: list = []
    datafile = ""
    searchdate = ""
    tmpfile = ""
    domains: list = []
    IPs: list = []

    def __init__(self, searchdate):
        self.searchdate = searchdate
        try:
            with open(triggerwords_yaml, 'r') as f:
                self.triggers = yaml.safe_load(f)
        except FileNotFoundError:
            LOG.fatal("triggerwords.yaml not found... aborting")
            raise SystemExit("triggerwords.yaml not found... aborting")

    def __openfile(self):
        file = f"{self.searchdate}.zip"
        # we need to unzip it
        zip = ZipFile(file)
        try:
            zip.extractall()
        except:
            LOG.critical("Domain list is not a valid zip file")
            raise SystemExit()
        return open('domain-names.txt', 'r')

        # commented out because it doesn't work... I was trying to write it into a tempfile
        # return zip.read('domain-names.txt')
        # .write(zip.read('))
        # return {name: zip.read(name) for name in zip.namelist()}

    def processmatches(self):
        self.downloaddata()
        # we've got the data
        self.searchdomains = [k for k in self.triggers['keywords']]
        # we've got the keywords

        for trigger in self.triggers['keywords']:
            # let's look for similar but different versions of the keyword list
            bitsquatting_search = self.__bitsquattng(trigger)
            hyphenation_search = self.__hyphenation(trigger)
            subdomain_search = self.__subdomain(trigger)
            # TODO: punycode?
            self.searchdomains += bitsquatting_search + hyphenation_search + subdomain_search
        # now let's append our static domains that we didn't want to generate variants for
        self.searchdomains += [k for k in self.triggers['static']]
        self.searchdomains.sort()
        LOG.debug(f"searching for matches against the following domain set {self.searchdomains}")
        fh = self.__openfile()

        for row in fh:
            # for each row in the file
            for argsearch in self.searchdomains:
                LOG.debug(f"matching against this arg: {argsearch}")
                if argsearch in row:
                    LOG.debug(f"matched {argsearch} in {row}")
                    domain = row.strip('\r\n')
                    # TODO check that there isn't already a MatchedDomain with a domain matching this domain
                    self.domains.append(MatchedDoman(domain, argsearch))
                    """ TODO should send the domain into a new parallelisable thread that retrieves the extra info 
                    rather than building a list and then iterating through that again later """
                    # match = re.search(r"^" + argsearch, row)
                    # if match:
                    #     domains.append(row.strip('\r\n'))
        self.get_DNS_record_results()
        # okay now we've got it... what are we gonaa do with it ????

    def __get_dns_data(self, domain):
        """
        get the DNS records for this domain
        """
        dnsresults = {}
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
                answer = resolver.query(domain, r)
                for answer in answer:
                    if r == 'A':
                        A.append(answer.address)
                        dnsresults.update({r: A})
                    if r == 'MX':
                        MX.append(answer.exchange.to_text()[:-1])
                        dnsresults.update({r: MX})
                    if r == 'NS':
                        NS.append(answer.target.to_text()[:-1])
                        dnsresults.update({r: NS})
                    if r == 'AAAA':
                        AAAA.append(answer.address)
                        dnsresults.update({r: AAAA})
                    if r == 'SOA':
                        SOA.append(answer.mname.to_text()[:-1])
                        dnsresults.update({r: SOA})
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
        return dnsresults

    def get_DNS_record_results(self):
        try:
            # this is a hack but the future_to_domain line isn't working
            domains = []
            for domain in self.domains:
                domains.append(domain.domain)

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.domains)) as executor:
                # future_to_domain = {executor.submit(self.__get_dns_data, domain): domain for domain in self.domains.get_domain}
                future_to_domain = {executor.submit(self.__get_dns_data, domain): domain for domain in domains}
                for future in concurrent.futures.as_completed(future_to_domain):
                    dom = future_to_domain[future]
                    try:
                        dns_record = future.result()
                        for k, v in dns_record.items():
                            for ip in v:
                                aa = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
                                if aa:
                                    self.IPs.append(ip)

                    except Exception as exc:
                        LOG.error(f"{dom} exception: {exc}")

        except ValueError:
            LOG.warning("ValueError exception in get_DNS_record_results")
            pass

    def __bitsquattng(self, search_word):
        out = []
        masks = [1, 2, 4, 8, 16, 32, 64, 128]

        for i in range(0, len(search_word)):
            c = search_word[i]
            for j in range(0, len(masks)):
                b = chr(ord(c) ^ masks[j])
                o = ord(b)
                if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                    out.append(search_word[:i] + b + search_word[i + 1:])
        return out

    def __hyphenation(self, search_word):
        LOG.debug(f"__hyphenation( {search_word} )")
        out = []
        for i in range(1, len(search_word)):
            out.append(search_word[:i] + '-' + search_word[i:])
        return out

    def __subdomain(self, search_word):
        LOG.debug(f"__subdomain( {search_word} )")
        out = []
        for i in range(1, len(search_word)):
            if search_word[i] not in ['-', '.'] and search_word[i - 1] not in ['-', '.']:
                out.append(search_word[:i] + '.' + search_word[i:])
        return out

    def downloaddata(self):
        searchdate = self.searchdate
        LOG.debug(sys._getframe().f_code.co_name)
        LOG.debug(f"downloaddata {searchdate}")
        if not os.path.isfile(searchdate + ".zip"):
            LOG.debug(f"file not found so let's try to download it")
            # file doesn't exist
            b64 = base64.b64encode((searchdate + ".zip").encode('ascii'))
            nrd_zip = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(
                b64.decode('ascii'))
            try:
                resp = requests.get(nrd_zip, stream=True)
                if len(resp.content) > 0:
                    LOG.info(f"Downloading File {searchdate}.zip - Size {resp.headers['Content-length']}...")
                    with open(searchdate + ".zip", 'wb') as f:
                        for data in resp.iter_content(chunk_size=1024):
                            f.write(data)
                else:
                    LOG.fatal("couldn't download file... maybe it doesn't exist on the remote server")
                    raise SystemExit("couldn't download file... maybe it doesn't exist on the remote server")
            except requests.exceptions.RequestException as e:
                raise SystemExit(e)
        else:
            LOG.debug("data file already available")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog="getdomains.py",
                                     description='lokok for matches on a given day')
    parser.add_argument("-f", action="store", dest='date', help="date [format: year-month-date]", required=True)
    parser.add_argument("-v", action="version", version="%(prog)s v0.1alpha")
    args = parser.parse_args()
    yyyymmdd_regex = re.compile('[\d]{4}-[\d]{2}-[\d]{2}$')
    IPs = []
    if re.match(yyyymmdd_regex, args.date):
        domain = DomainLookup(args.date)
        #
        domain.processmatches()

    else:
        print(f"Invalid date format, use yyyy-mm-dd format")
        sys.exit()
