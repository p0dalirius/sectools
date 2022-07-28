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
        bits_mask = int(matched.groups()[-1])
    else:
        print("[!] Invalid CIDR '%s'" % cidr)
        return []


# IP conversion functions


def ipv4_str_to_hex_str(ipv4) -> str:
    a, b, c, d = map(int, ipv4.split('.'))
    hexip = hex(a)[2:].rjust(2,'0')
    hexip += hex(b)[2:].rjust(2, '0')
    hexip += hex(c)[2:].rjust(2, '0')
    hexip += hex(d)[2:].rjust(2, '0')
    return hexip


def ipv4_str_to_raw_bytes(ipv4) -> bytes:
    a, b, c, d = map(int, ipv4.split('.'))
    return bytes([a, b, c, d])


def ipv4_str_to_int(ipv4) -> bytes:
    a, b, c, d = map(int, ipv4.split('.'))
    return (a<<24) + (b<<16) + (c<<8) + d