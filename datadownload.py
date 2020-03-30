import argparse
import re
import sys
import os
import base64
import requests

def download(searchdate):
    if not os.path.isfile(searchdate + ".zip"):
        print(f"file not found so let's try to download it")
        # file doesn't exist
        b64 = base64.b64encode((searchdate + ".zip").encode('ascii'))
        nrd_zip = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(b64.decode('ascii'))
        try:
            resp = requests.get(nrd_zip, stream=True)
            if len(resp.content) > 0:
                print(f"Downloading File {searchdate}.zip - Size {resp.headers['Content-length']}...")
                with open(searchdate + ".zip", 'wb') as f:
                    for data in resp.iter_content(chunk_size=1024):
                        f.write(data)
            else:
                raise SystemExit("couldn't download file... maybe it doesn't exist on the remote server")
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="datadownload.py",
                                     description='download a daily export of newly registered domains')
    parser.add_argument("-f", action="store", dest='date', help="date [format: year-month-date]", required=True)
    parser.add_argument("-v", action="version", version="%(prog)s v0.1alpha")
    args = parser.parse_args()

    yyyymmdd_regex = re.compile('[\d]{4}-[\d]{2}-[\d]{2}$')
    if re.match(yyyymmdd_regex, args.date):
        download(args.date)
    else:
        print(f"Invalid date format, use yyyy-mm-dd format")
        sys.exit()
