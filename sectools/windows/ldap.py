#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldap.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jul 2022


from sectools.windows.crypto import parse_lm_nt_hashes
import binascii
import ldap3
import logging
import os
import ssl


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


def get_computers_from_domain(auth_domain, auth_dc_ip, auth_username, auth_password, auth_hashes, use_ldaps=False, __print=False):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_ldaps=use_ldaps
    )

    if __print:
        print("[>] Extracting all computers ...")

    computers = []
    searchbase = ldap_server.info.other["defaultNamingContext"]
    results = list(ldap_session.extend.standard.paged_search(searchbase, "(objectCategory=computer)", attributes=["dNSHostName"]))
    for entry in results:
        if entry['type'] != 'searchResEntry':
            continue
        dNSHostName = entry["attributes"]['dNSHostName']
        if type(dNSHostName) == str:
            computers.append(dNSHostName)
        if type(dNSHostName) == list:
            if len(dNSHostName) != 0:
                for entry in dNSHostName:
                    computers.append(entry)

    if __print:
        print("[+] Found %d computers in the domain." % len(computers))

    return computers


def get_servers_from_domain(auth_domain, auth_dc_ip, auth_username, auth_password, auth_hashes, use_ldaps=False, __print=False):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_ldaps=use_ldaps
    )

    if __print:
        print("[>] Extracting all servers ...")

    servers = []
    searchbase = ldap_server.info.other["defaultNamingContext"]
    results = list(ldap_session.extend.standard.paged_search(searchbase, "(&(objectCategory=computer)(operatingSystem=*Server*))",attributes=["dNSHostName"]))
    for entry in results:
        if entry['type'] != 'searchResEntry':
            continue
        dNSHostName = entry["attributes"]['dNSHostName']
        if type(dNSHostName) == str:
            servers.append(dNSHostName)
        if type(dNSHostName) == list:
            if len(dNSHostName) != 0:
                for entry in dNSHostName:
                    servers.append(entry)

    if __print:
        print("[+] Found %d servers in the domain." % len(servers))

    return servers


def get_subnets(auth_domain, auth_dc_ip, auth_username, auth_password, auth_hashes, use_ldaps=False, __print=False):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_ldaps=use_ldaps
    )

    if __print:
        print("[>] Extracting all subnets ...")

    subnets = []
    searchbase = ldap_server.info.other["configurationNamingContext"]
    results = list(ldap_session.extend.standard.paged_search(searchbase, "(objectClass=site)",attributes=['distinguishedName', 'name', 'description']))
    sites = []
    for entry in results:
        if entry['type'] != 'searchResEntry':
            continue
        sites.append((entry["dn"], entry["attributes"]["name"]))

    subnets = []
    for site_dn, site_name in sites:
        results = list(ldap_session.extend.standard.paged_search(
            "CN=Sites,"+ldap_server.info.other["configurationNamingContext"][0],
            '(siteObject=%s)' % site_dn,
            attributes=['distinguishedName', 'name', 'description'])
        )
        for entry in results:
            if entry['type'] != 'searchResEntry':
                continue
            subnets.append(entry["attributes"]["name"])

    if __print:
        print("[+] Found %d subnets in the domain." % len(subnets))

    return subnets


def raw_ldap_query(auth_domain, auth_dc_ip, auth_username, auth_password, auth_hashes, query, attributes=['*'], searchbase=None, use_ldaps=False):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_ldaps=use_ldaps
    )
    
    if searchbase is None:
        searchbase = ldap_server.info.other["defaultNamingContext"]
    
    ldapresults = list(ldap_session.extend.standard.paged_search(searchbase, query, attributes=attributes))

    results = {}
    for entry in ldapresults:
        if entry['type'] != 'searchResEntry':
            continue
        results[entry['dn']] = entry["attributes"]

    return results
