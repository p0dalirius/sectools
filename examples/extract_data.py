#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : extract_data.py
# Author             : Podalirius (@podalirius_)
# Date created       : 25 Sep 2021

import argparse
import json
import os
import re
import sys
import requests
import sectools.data.regex


def parseArgs():
    parser = argparse.ArgumentParser(description="Extract data from a file or URL")
    #
    group_ex = parser.add_mutually_exclusive_group(required=True)
    group_ex.add_argument("-u", "--url", default=None, type=str, help='arg1 help message')
    group_ex.add_argument("-f", "--file", default=None, type=str, help='File to extract data from (can be raw bytes)')
    #
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='arg1 help message')
    parser.add_argument("-o", "--output", default="found_data.json", type=str, help='Output JSON file (default: found_data.json)')
    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    data = None
    if options.url is not None:
        if options.verbose == True:
            print("[+] GET %s ... " % options.url, end="")
            sys.stdout.flush()
        r = requests.get(options.url)
        data = r.content
        if options.verbose == True:
            print("done.")
    elif options.file is not None:
        if options.verbose == True:
            print("[+] Reading file %s ... " % options.file, end="")
            sys.stdout.flush()
        f = open(options.file, "rb")
        data = f.read()
        f.close()
        if options.verbose == True:
            print("done.")

    if data is not None:
        found = {
            'emails': [],
            'urls': [],
            'domains': [],
            'ipv4': [],
            'ipv6': [],
            'mac': []
        }

        # Searching for emails
        matched = re.findall(sectools.data.regex.regex_email_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d emails." % len(matched))
                # print(matched)
            found['emails'] = list(set([m for m in matched if len(m) != 0]))

        # Searching for URLs
        matched = re.findall(sectools.data.regex.regex_url_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d URLs." % len(matched))
                # print(matched)
            found['urls'] = list(set([m for m in matched if len(m) != 0]))

        # Searching for domains
        matched = re.findall(sectools.data.regex.regex_domain_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d domains." % len(matched))
                # print(matched)
            found['domains'] = list(set([m for m in matched if len(m) != 0]))
        #
        matched = re.findall(sectools.data.regex.regex_mac_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d MAC addresses." % len(matched))
                # print(matched)
            found['mac'] = list(set([m for m in matched if len(m) != 0]))
        #
        matched = re.findall(sectools.data.regex.regex_ipv4_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d IPv4." % len(matched))
                # print(matched)
            found['ipv4'] = list(set([m for m in matched if len(m) != 0]))
        #
        matched = re.findall(sectools.data.regex.regex_ipv6_b, data)
        matched = [m[0] for m in matched if len(m[0]) != 0]
        if matched is not None and len(matched) != 0:
            if options.verbose == True:
                print("[+] Found %d IPv6." % len(matched))
                # print(matched)
            found['ipv6'] = list(set([m for m in matched if len(m) != 0]))

        for key in found.keys():
            found[key] = [e.decode("UTF-8") for e in found[key]]

        if len(os.path.dirname(options.output)) != 0:
            if not os.path.exists(os.path.dirname(options.output)):
                os.makedirs(os.path.dirname(options.output), exist_ok=True)
        f = open(options.output, 'w')
        f.write(json.dumps(found, indent=4))
        f.close()
    else:
        print("[!] Data is None. Cannot continue.")