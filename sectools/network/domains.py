#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : domains.py
# Author             : Podalirius (@podalirius_)
# Date created       : 2 Aug 2022

import re
from sectools.data.regex import regex_domain


def is_fqdn(target):
    outcome = False
    matched = re.match("^" + regex_domain + "$", target.strip())
    if matched is not None:
        outcome = True
    return outcome
