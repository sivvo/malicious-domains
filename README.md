*work in progress*

This script looks for newly registered domains that might be malicious or used for phishing.

It matches against words that have been defined in triggerwords.yaml.
Triggerwords.yaml has 2 main sections:
- keywords
- static

Anything defined as a keyword will have various permutations of the word generated (for example, hyphenated
entries, bitsquatting and the like)

The static entries do not undergo permutation generation, they simply match the static word.

The rational is that genuine domains with these words don't get created on a newly basis. 

First we match against the static words, key words and permutations of keywords. If we find a match we create an
instance of Matched Domain. These instances will load in metadata (dns records, whois, ASN lookup) as well as creating
shannon entropy and levenshtein scores. 

Only those that score above a given confidence level will be logged to Splunk (TODO)

Right now the script is dog slow because of the whois library. The logic will have to change to only perform some
enrichment operations after we already have confidence in it being a malicious domain.

usage:
getdomains.py -d YYYY-mm-dd