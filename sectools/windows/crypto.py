#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : crypto.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jul 2022

import re
import hashlib


def parse_lm_nt_hashes(lm_nt_hashes_string):
    lm_hash_value, nt_hash_value = "", ""
    if lm_nt_hashes_string is not None:
        matched = re.match("([0-9a-f]{32})?(:)?([0-9a-f]{32})?", lm_nt_hashes_string.strip().lower())
        m_lm_hash, _, m_nt_hash = matched.groups()
        if m_lm_hash is None and m_nt_hash is not None:
            lm_hash_value = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash_value = m_nt_hash
        elif m_lm_hash is not None and m_nt_hash is None:
            lm_hash_value = m_lm_hash
            nt_hash_value = nt_hash("")
        else:
            lm_hash_value = m_lm_hash
            nt_hash_value = m_nt_hash
    return lm_hash_value, nt_hash_value


def nt_hash(data):
    if type(data) == str:
        data = bytes(data, 'utf-16-le')

    ctx = hashlib.new('md4', data)
    nt_hash_value = ctx.hexdigest()

    return nt_hash_value
