#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ip.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2022

import re
from sectools.data.regex import regex_ipv4, regex_ipv4_cidr, regex_ipv6


def is_ipv4_cidr(target) -> bool:
    outcome = False
    matched = re.match("^" + regex_ipv4_cidr + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def is_ipv4_addr(target) -> bool:
    outcome = False
    matched = re.match("^" + regex_ipv4 + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def is_ipv6_addr(target):
    outcome = False
    matched = re.match("^" + regex_ipv6 + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def expand_cidr(cidr):
    if is_ipv4_cidr(cidr):
        matched = re.match("^" + regex_ipv4_cidr + "$", cidr.strip())
        network_ip = matched.groups()[0]
        network_ip_int = ipv4_str_to_int(network_ip)
        bits_mask = int(matched.groups()[-1])
        # Applying bitmask
        network_ip_int = (network_ip_int >> (32 - bits_mask)) << (32 - bits_mask)
        addresses = [ipv4_int_to_str(network_ip_int + k) for k in range(2 ** (32-bits_mask))]
        return addresses
    else:
        print("[!] Invalid CIDR '%s'" % cidr)
        return []


# IP conversion functions


def ipv4_str_to_hex_str(ipv4) -> str:
    a, b, c, d = map(int, ipv4.split('.'))
    hexip = hex(a)[2:].rjust(2, '0')
    hexip += hex(b)[2:].rjust(2, '0')
    hexip += hex(c)[2:].rjust(2, '0')
    hexip += hex(d)[2:].rjust(2, '0')
    return hexip


def ipv4_str_to_raw_bytes(ipv4) -> bytes:
    a, b, c, d = map(int, ipv4.split('.'))
    return bytes([a, b, c, d])


def ipv4_str_to_int(ipv4) -> bytes:
    a, b, c, d = map(int, ipv4.split('.'))
    return (a << 24) + (b << 16) + (c << 8) + d


def ipv4_int_to_str(ipv4) -> str:
    a = (ipv4 >> 24) & 0xff
    b = (ipv4 >> 16) & 0xff
    c = (ipv4 >> 8) & 0xff
    d = (ipv4 >> 0) & 0xff
    return "%d.%d.%d.%d" % (a, b, c, d)
