#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Markdown.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Nov 2022

import os
import re


class Markdown(object):
    """
    Documentation for class Markdown
    """

    data = None

    def __init__(self, data):
        super(Markdown, self).__init__()
        self.data = data

    @classmethod
    def fromFile(cls, path_to_file):
        if os.path.exists(path_to_file):
            f = open(path_to_file, 'r')
            self = cls(data=f.read())
            f.close()
            return self
        else:
            return None

    @classmethod
    def fromData(cls, data):
        self = cls(data=data)
        return self

    def extract_links(self):
        found = []
        if self.data is not None:
            for match in re.findall(r'[^!](\[([^\]]*)\]\(([^)]*)\))|(^\[([^\]]*)\]\(([^)]*)\))', self.data):
                if len(match[0]) != 0:
                    md_format, text, link = match[:3]
                    found.append({"markdown": md_format, "text": text, "link": link})
                elif len(match[3]) != 0:
                    md_format, text, link = match[3:]
                    found.append({"markdown": md_format, "text": text, "link": link})
        return found

    def extract_images(self):
        found = []
        if self.data is not None:
            for match in re.findall(r'(!\[([^\]]*)\]\(([^)]*)\))', self.data):
                md_format, text, link = match
                found.append({"markdown": md_format, "text": text, "link": link})
        return found
