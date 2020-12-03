from __future__ import print_function
import os
import yaml
import logging
from matchdomains import MatchedDomain
import concurrent.futures
import requests
import requests_random_user_agent

LOG = logging.getLogger('getdomains.log')
LOG.setLevel(logging.INFO)
FORMATTER = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr = logging.FileHandler('getdomains.log')
hdlr.setFormatter(FORMATTER)
hdlr.setLevel(logging.INFO)
LOG.addHandler(hdlr)
LOG.addHandler(logging.StreamHandler())

BEARER_TOKEN = os.getenv('BEARER_TOKEN')
triggerwords_yaml = os.path.dirname(os.path.realpath(__file__)) + '/triggerwords.yaml'

##############################
# Call this with a domain, regardless of origin
# It will build a list of triggerwords and then review the URL
##############################
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

    def __init__(self):
        try:
            with open(triggerwords_yaml, 'r') as f:
                self.triggers = yaml.safe_load(f)
        except FileNotFoundError:
            LOG.fatal("triggerwords.yaml not found... aborting")
            raise SystemExit("triggerwords.yaml not found... aborting")

        self.searchdomains = [k for k in self.triggers['keywords']]
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

    def process(self, domain):
        for argsearch in self.searchdomains:
            LOG.debug(f"matching against this arg: {argsearch}")
            if argsearch in domain:
                LOG.debug(f"matched {argsearch} in {domain}")
                domain = domain.strip('\r\n')

                # TODO check that there isn't already a MatchedDomain with a domain matching this domain
                self.domains.append(MatchedDomain(domain, argsearch))
                """ TODO should send the domain into a new parallelisable thread that retrieves the extra info 
                rather than building a list and then iterating through that again later """
                # match = re.search(r"^" + argsearch, row)
                # if match:
                #     domains.append(row.strip('\r\n'))

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.domains)+1) as executor:
            future_to_enrich = {executor.submit(domain.enrich()): domain for domain in self.domains}

        filtered_list = list(filter(lambda domains: domains.score > 60, self.domains))
        filtered_list.sort(key=lambda domains: domains.score)
        domains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(filtered_list)+1) as executor:
                future_to_enrich = {executor.submit(self.__checkURL(domain.domain)): domain for domain in filtered_list}

    ##############################
    # bearerauth
    ##############################
    class BearerAuth(requests.auth.AuthBase):
        def __init__(self, token):
            self.token = token

        def __call__(self, r):
            r.headers["authorization"] = "Bearer " + BEARER_TOKEN
            return r

    def __checkURL(self, domainToCheck):
        if BEARER_TOKEN is None:
            print(f"Bearer token hasn't been set, cannot call the API")
        else:
            try:
                print(f"Checking url for {domainToCheck}")
                r = requests.get(f'https://csa.staging.gds-cyber-security.digital/checkdomain/?url=https://{domainToCheck}',
                                 auth=self.BearerAuth(BEARER_TOKEN))
                print(r.status_code)
                print(r.text)
            except:
                print(f"error trying to test {domainToCheck}")
        #pprint(r)