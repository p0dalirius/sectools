#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldap.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jul 2022


import binascii
import ldap3
import logging
import os
import ssl


def get_machine_name(auth_domain, auth_dc_ip):
    if auth_dc_ip is not None:
        s = SMBConnection(auth_dc_ip, auth_dc_ip)
    else:
        s = SMBConnection(auth_domain, auth_domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % auth_domain)
    else:
        s.logoff()
    return s.getServerName()


def __init_ldap_connection(target, tls_version, dc_ip, domain, username, password, lmhash, nthash, use_ldaps=False, auth_key=None):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)

    if len(nthash) != 0:
        if len(lmhash) == 0:
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(auth_domain, auth_dc_ip, auth_username, auth_password, auth_lm_hash, auth_nt_hash, use_ldaps=False):
    target_dc = (auth_dc_ip if auth_dc_ip is not None else auth_domain)

    if use_ldaps is True:
        try:
            return __init_ldap_connection(
                target=target_dc,
                tls_version=ssl.PROTOCOL_TLSv1_2,
                dc_ip=auth_dc_ip,
                domain=auth_domain,
                username=auth_username,
                password=auth_password,
                lmhash=auth_lm_hash,
                nthash=auth_nt_hash
            )
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return __init_ldap_connection(
                target=target_dc,
                tls_version=ssl.PROTOCOL_TLSv1,
                dc_ip=auth_dc_ip,
                domain=auth_domain,
                username=auth_username,
                password=auth_password,
                lmhash=auth_lm_hash,
                nthash=auth_nt_hash
            )
    else:
        return __init_ldap_connection(
            target=target_dc,
            tls_version=None,
            dc_ip=auth_dc_ip,
            domain=auth_domain,
            username=auth_username,
            password=auth_password,
            lmhash=auth_lm_hash,
            nthash=auth_nt_hash
        )


def get_computers_from_domain(auth_domain, auth_dc_ip, auth_username, auth_password, auth_hashes):

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_kerberos=False,
        use_ldaps=False
    )

    print("[>] Extracting all computers ...")

    computers = []
    target_dn = ldap_server.info.other["defaultNamingContext"]
    ldap_session.search(target_dn, "(objectCategory=computer)", attributes=["dNSHostName"])
    for entry in ldap_session.response:
        if entry['type'] != 'searchResEntry':
            continue
        computers.append(entry["attributes"]['dNSHostName'])

    print("[+] Found %d computers in the domain." % len(computers))

    return computers
