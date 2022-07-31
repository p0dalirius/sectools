#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : crypto.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jul 2022

def parse_lm_nt_hashes(lm_nt_hashes_string):
    lm_hash = ""
    nt_hash = ""
    if hashes is not None:
        if ":" in hashes:
            lm_hash = hashes.split(":")[0]
            nt_hash = hashes.split(":")[1]
        else:
            nt_hash = hashes
