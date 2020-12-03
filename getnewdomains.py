from __future__ import print_function
import sys
import argparse
import re
import logging
import requests
import requests_random_user_agent
import os
import base64
from zipfile import ZipFile
from domainlookup import DomainLookup

LOG = logging.getLogger('getdomains.log')
LOG.setLevel(logging.INFO)
FORMATTER = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr = logging.FileHandler('getdomains.log')
hdlr.setFormatter(FORMATTER)
hdlr.setLevel(logging.INFO)
LOG.addHandler(hdlr)
LOG.addHandler(logging.StreamHandler())

class NewDomains:
    """
    Initialise the class with a date in the format YYYY-mm-dd
    Methods: processmatches

    """
    searchdomains: list = []
    datafile = ""
    searchdate = ""
    tmpfile = ""
    domains: list = []
    IPs: list = []

    def __init__(self, searchdate):
        self.searchdate = searchdate
        self.domainlookup = DomainLookup()

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
        fh = self.__openfile()
        for row in fh:
            print(row)
            self.domainlookup.process(row)
            #TODO CALL DomainLookup

    def downloaddata(self):
        searchdate = self.searchdate
        LOG.debug(sys._getframe().f_code.co_name)
        LOG.debug(f"downloaddata {searchdate}")
        if not os.path.isfile(searchdate + ".zip"):
            LOG.debug(f"file not found so let's try to download it")
            # file doesn't exist
            b64 = base64.b64encode((searchdate + ".zip").encode('ascii'))
            nrd_zip = 'https://www.whoisdownload.com/download-panel/free-download-file/{}/nrd/home'.format(
                b64.decode('ascii'))
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"}
            try:
                resp = requests.get(nrd_zip, stream=True, headers=headers)
                if len(resp.content) > 0:
                    # LOG.info(f"Downloading File {searchdate}.zip - Size {resp.headers['Content-length']}...")
                    LOG.info(f"Downloading File {searchdate}.zip - Size {len(resp.content)}...")
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

    parser = argparse.ArgumentParser(prog="getnewdomains.py",
                                     description='look for matches on a given day')
    parser.add_argument("-d", action="store", dest='date', help="date [format: year-month-date]", required=True)
    parser.add_argument("-v", action="version", version="%(prog)s v0.1alpha")
    args = parser.parse_args()
    yyyymmdd_regex = re.compile('[\d]{4}-[\d]{2}-[\d]{2}$')
    if re.match(yyyymmdd_regex, args.date):
        newdomains = NewDomains(args.date)
        #
        newdomains.processmatches()

    else:
        print(f"Invalid date format, use yyyy-mm-dd format")
        sys.exit()