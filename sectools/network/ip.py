#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ip.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2022

import re

from sectools.data.regex import regex_ipv4, regex_ipv4_cidr, regex_ipv6


def is_ipv4_cidr(target) -> bool:
    """
    Check if the target is a valid IPv4 CIDR notation address.

    Args:
        target (str): The string to check

    Returns:
        bool: True if target is valid IPv4 CIDR notation, False otherwise
    """
    outcome = False
    matched = re.match("^" + regex_ipv4_cidr + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def is_ipv4_addr(target) -> bool:
    """
    Check if the target is a valid IPv4 address.

    Args:
        target (str): The string to check

    Returns:
        bool: True if target is valid IPv4 address, False otherwise
    """
    outcome = False
    matched = re.match("^" + regex_ipv4 + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def is_ipv6_addr(target):
    """
    Check if the target is a valid IPv6 address.

    Args:
        target (str): The string to check

    Returns:
        bool: True if target is valid IPv6 address, False otherwise
    """
    outcome = False
    matched = re.match("^" + regex_ipv6 + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome


def expand_cidr(cidr):
    """
    Expands a CIDR notation address into a list of all individual IPv4 addresses in that range.

    Args:
        cidr (str): CIDR notation address (e.g. "192.168.1.0/24")

    Returns:
        list: List of IPv4 addresses as strings, empty list if invalid CIDR
    """
    if is_ipv4_cidr(cidr):
        matched = re.match("^" + regex_ipv4_cidr + "$", cidr.strip())
        network_ip = matched.groups()[0]
        network_ip_int = ipv4_str_to_int(network_ip)
        bits_mask = int(matched.groups()[-1])
        # Applying bitmask
        network_ip_int = (network_ip_int >> (32 - bits_mask)) << (32 - bits_mask)
        addresses = [
            ipv4_int_to_str(network_ip_int + k) for k in range(2 ** (32 - bits_mask))
        ]
        return addresses
    else:
        print("[!] Invalid CIDR '%s'" % cidr)
        return []


def expand_port_range(port_range):
    """
    Expands a port range string into a list of individual port numbers.

    Args:
        port_range (str): Port range string (e.g. "80", "1-1024", "-1024", "1024-", "-")

    Returns:
        list: List of port numbers in the range
    """
    port_range = port_range.strip()
    ports = []
    matched = re.match("([0-9]+)?(-)?([0-9]+)?", port_range)
    if matched is not None:
        start, sep, stop = matched.groups()
        if start is not None and (sep is None and stop is None):
            # Single port
            start = int(start)
            if 0 <= start <= 65535:
                ports = [start]
        elif (start is not None and sep is not None) and stop is None:
            # Port range from start to 65535
            start = int(start)
            if 0 <= start <= 65535:
                ports = list(range(start, 65535 + 1))
        elif start is None and (sep is not None and stop is not None):
            # Port range from 0 to stop
            stop = int(stop)
            if 0 <= stop <= 65535:
                ports = list(range(0, stop + 1))
        elif start is not None and sep is not None and stop is not None:
            # Port range from start to stop
            start = int(start)
            stop = int(stop)
            if 0 <= start <= 65535 and 0 <= stop <= 65535:
                ports = list(range(start, stop + 1))
        elif start is None and sep is not None and stop is None:
            # Port range from 0 to 65535
            ports = list(range(0, 65535 + 1))
    return ports


# IP conversion functions


def ipv4_str_to_hex_str(ipv4) -> str:
    """
    Convert an IPv4 address string to hexadecimal string representation.

    Args:
        ipv4 (str): IPv4 address string (e.g. "192.168.1.1")

    Returns:
        str: Hexadecimal string representation of the IPv4 address
    """
    a, b, c, d = map(int, ipv4.split("."))
    hexip = hex(a)[2:].rjust(2, "0")
    hexip += hex(b)[2:].rjust(2, "0")
    hexip += hex(c)[2:].rjust(2, "0")
    hexip += hex(d)[2:].rjust(2, "0")
    return hexip


def ipv4_str_to_raw_bytes(ipv4) -> bytes:
    """
    Convert an IPv4 address string to raw bytes.

    Args:
        ipv4 (str): IPv4 address string (e.g. "192.168.1.1")

    Returns:
        bytes: Raw bytes representation of the IPv4 address
    """
    a, b, c, d = map(int, ipv4.split("."))
    return bytes([a, b, c, d])


def ipv4_str_to_int(ipv4) -> bytes:
    """
    Convert an IPv4 address string to 32-bit integer.

    Args:
        ipv4 (str): IPv4 address string (e.g. "192.168.1.1")

    Returns:
        int: 32-bit integer representation of the IPv4 address
    """
    a, b, c, d = map(int, ipv4.split("."))
    return (a << 24) + (b << 16) + (c << 8) + d


def ipv4_int_to_str(ipv4) -> str:
    """
    Convert a 32-bit integer to IPv4 address string.

    Args:
        ipv4 (int): 32-bit integer representation of IPv4 address

    Returns:
        str: IPv4 address string (e.g. "192.168.1.1")
    """
    a = (ipv4 >> 24) & 0xFF
    b = (ipv4 >> 16) & 0xFF
    c = (ipv4 >> 8) & 0xFF
    d = (ipv4 >> 0) & 0xFF
    return "%d.%d.%d.%d" % (a, b, c, d)
