from __future__ import print_function
import logging
import argparse
import sys
import datetime
import certstream
from domainlookup import DomainLookup

LOG = logging.getLogger('getdomains.log')
LOG.setLevel(logging.INFO)
FORMATTER = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr = logging.FileHandler('getdomains.log')
hdlr.setFormatter(FORMATTER)
hdlr.setLevel(logging.INFO)
LOG.addHandler(hdlr)
LOG.addHandler(logging.StreamHandler())

class CertStream:
    """
    Initialise the class with a date in the format YYYY-mm-dd
    Methods: processmatches

    """
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    def __init__(self):
        self.domainlookup = DomainLookup()
        certstream.listen_for_events(self.print_callback, url='wss://certstream.calidog.io/')


    def print_callback(self, message, context):
        logging.debug("Message -> {}".format(message))

        if message['message_type'] == "heartbeat":
            return

        if message['message_type'] == "certificate_update":
            all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]
        if domain[:2] == "*.":
            domain = domain[2:]
        self.domainlookup.process(domain)
        sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain,", ".join(message['data']['leaf_cert']['all_domains'][1:])))
        #sys.stdout.flush()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog="getcertstream.py",
                                     description='look for matches based on live certstream')
    args = parser.parse_args()
    certstream = CertStream()