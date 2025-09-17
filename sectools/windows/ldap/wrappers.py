#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : wrappers.py
# Author             : Podalirius (@podalirius_)
# Date created       : 2 Aug 2022


from sectools.windows.crypto import parse_lm_nt_hashes
from sectools.windows.ldap import init_ldap_session


def get_computers_from_domain(
    auth_domain,
    auth_dc_ip,
    auth_username,
    auth_password,
    auth_hashes,
    auth_key=None,
    use_kerberos=False,
    kdcHost=None,
    use_ldaps=False,
    __print=False,
):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        auth_key=auth_key,
        use_kerberos=use_kerberos,
        kdcHost=kdcHost,
        use_ldaps=use_ldaps,
    )

    if __print:
        print("[>] Extracting all computers ...")

    computers = []
    searchbase = ldap_server.info.other["defaultNamingContext"]
    results = list(
        ldap_session.extend.standard.paged_search(
            searchbase, "(objectCategory=computer)", attributes=["dNSHostName"]
        )
    )
    for entry in results:
        if entry["type"] != "searchResEntry":
            continue
        dNSHostName = entry["attributes"]["dNSHostName"]
        if isinstance(dNSHostName, str):
            computers.append(dNSHostName)
        if isinstance(dNSHostName, list):
            if len(dNSHostName) != 0:
                for entry in dNSHostName:
                    computers.append(entry)

    if __print:
        print("[+] Found %d computers in the domain." % len(computers))

    return computers


def get_servers_from_domain(
    auth_domain,
    auth_dc_ip,
    auth_username,
    auth_password,
    auth_hashes,
    auth_key=None,
    use_kerberos=False,
    kdcHost=None,
    use_ldaps=False,
    __print=False,
):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        auth_key=auth_key,
        use_kerberos=use_kerberos,
        kdcHost=kdcHost,
        use_ldaps=use_ldaps,
    )

    if __print:
        print("[>] Extracting all servers ...")

    servers = []
    searchbase = ldap_server.info.other["defaultNamingContext"]
    results = list(
        ldap_session.extend.standard.paged_search(
            searchbase,
            "(&(objectCategory=computer)(operatingSystem=*Server*))",
            attributes=["dNSHostName"],
        )
    )
    for entry in results:
        if entry["type"] != "searchResEntry":
            continue
        dNSHostName = entry["attributes"]["dNSHostName"]
        if isinstance(dNSHostName, str):
            servers.append(dNSHostName)
        if isinstance(dNSHostName, list):
            if len(dNSHostName) != 0:
                for entry in dNSHostName:
                    servers.append(entry)

    if __print:
        print("[+] Found %d servers in the domain." % len(servers))

    return servers


def get_subnets(
    auth_domain,
    auth_dc_ip,
    auth_username,
    auth_password,
    auth_hashes,
    auth_key=None,
    use_kerberos=False,
    kdcHost=None,
    use_ldaps=False,
    __print=False,
):
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(auth_hashes)

    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        auth_key=auth_key,
        use_kerberos=use_kerberos,
        kdcHost=kdcHost,
        use_ldaps=use_ldaps,
    )

    if __print:
        print("[>] Extracting all subnets ...")

    subnets = []
    searchbase = ldap_server.info.other["configurationNamingContext"]
    results = list(
        ldap_session.extend.standard.paged_search(
            searchbase,
            "(objectClass=site)",
            attributes=["distinguishedName", "name", "description"],
        )
    )
    sites = []
    for entry in results:
        if entry["type"] != "searchResEntry":
            continue
        sites.append((entry["dn"], entry["attributes"]["name"]))

    subnets = []
    for site_dn, site_name in sites:
        results = list(
            ldap_session.extend.standard.paged_search(
                "CN=Sites," + ldap_server.info.other["configurationNamingContext"][0],
                "(siteObject=%s)" % site_dn,
                attributes=["distinguishedName", "name", "description"],
            )
        )
        for entry in results:
            if entry["type"] != "searchResEntry":
                continue
            subnets.append(entry["attributes"]["name"])

    if __print:
        print("[+] Found %d subnets in the domain." % len(subnets))

    return subnets
