#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldap.py
# Author             : Podalirius (@podalirius_)
# Date created       : 30 Jul 2022


import ssl

import ldap3

from sectools.windows.crypto import parse_lm_nt_hashes


def ldap3_kerberos_login(
    connection,
    target,
    user,
    password,
    domain="",
    lmhash="",
    nthash="",
    aesKey="",
    kdcHost=None,
    TGT=None,
    TGS=None,
    useCache=True,
):
    from pyasn1.codec.ber import decoder, encoder
    from pyasn1.type.univ import noValue

    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    # Importing down here so pyasn1 is not required if kerberos is not used.
    import datetime

    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

    if TGT is not None or TGS is not None:
        useCache = False

    targetName = "ldap/%s" % target
    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, password, domain, lmhash, nthash, aesKey, kdcHost
            )
    else:
        tgt = TGT["KDC_REP"]
        cipher = TGT["cipher"]
        sessionKey = TGT["sessionKey"]

    if TGS is None:
        serverName = Principal(
            targetName, type=constants.PrincipalNameType.NT_SRV_INST.value
        )
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
            serverName, domain, kdcHost, tgt, cipher, sessionKey
        )
    else:
        tgs = TGS["KDC_REP"]
        cipher = TGS["cipher"]
        sessionKey = TGS["sessionKey"]

    # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq["ap-options"] = constants.encodeFlags(opts)
    seq_set(apReq, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(
        sessionKey, 11, encodedAuthenticator, None
    )

    apReq["authenticator"] = noValue
    apReq["authenticator"]["etype"] = cipher.enctype
    apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

    blob["MechToken"] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(
        connection.version, ldap3.SASL, user, None, "GSS-SPNEGO", blob.getData()
    )

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(
        connection.send("bindRequest", request, None)
    )
    connection.sasl_in_progress = False
    if response[0]["result"] != 0:
        raise Exception(response)

    connection.bound = True

    return True


def __init_ldap_connection(
    target,
    tls_version,
    domain,
    username,
    password,
    lmhash,
    nthash,
    aesKey=None,
    kerberos=False,
    kdcHost=None,
):
    DEBUG = False

    if nthash is None:
        nthash = ""
    if lmhash is None:
        lmhash = ""

    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(
            validate=ssl.CERT_NONE, version=tls_version, ciphers="ALL:@SECLEVEL=0"
        )
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(
        host=target, port=port, use_ssl=use_ssl, get_info=ldap3.ALL, tls=tls
    )

    ldap_session = None

    if kerberos:
        if DEBUG:
            print("[%s] Using Kerberos authentication" % __name__)
            print("   | target", target)
            print("   | username", username)
            print("   | password", password)
            print("   | domain", domain)
            print("   | lmhash", lmhash)
            print("   | nthash", nthash)
            print("   | aesKey", aesKey)
            print("   | kdcHost", kdcHost)

        ldap_session = ldap3.Connection(server=ldap_server)
        ldap_session.bind()

        ldap3_kerberos_login(
            connection=ldap_session,
            target=target,
            user=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aesKey,
            kdcHost=kdcHost,
        )

    elif any([len(nthash) != 0, len(lmhash) != 0]):
        if DEBUG:
            print("[%s] Using Pass the Hash authentication" % __name__)
        if len(lmhash) == 0:
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        if len(nthash) == 0:
            nthash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        try:
            ldap_session = ldap3.Connection(
                server=ldap_server,
                user="%s\\%s" % (domain, username),
                password=lmhash + ":" + nthash,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
        except ldap3.core.exceptions.LDAPBindError as e:
            if "strongerAuthRequired" in str(e):  # to handle ldap signing on port 389
                if DEBUG:
                    print("[%s] Trying to handle LDAP signing" % __name__)
                ldap_session = ldap3.Connection(
                    server=ldap_server,
                    user="%s\\%s" % (domain, username),
                    password=lmhash + ":" + nthash,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    session_security="ENCRYPT",
                )
            elif port == 636 and "invalidCredentials" in str(
                e
            ):  # to handle channel binding on port 636 (Exception is not different from truly invalid credentials...)
                if DEBUG:
                    print("[%s] Trying to handle channel binding" % __name__)
                ldap_session = ldap3.Connection(
                    server=ldap_server,
                    user="%s\\%s" % (domain, username),
                    password=lmhash + ":" + nthash,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    channel_binding=ldap3.TLS_CHANNEL_BINDING,
                )
            else:
                raise

    else:
        if DEBUG:
            print("[%s] Using user/password authentication" % __name__)
        try:
            ldap_session = ldap3.Connection(
                server=ldap_server,
                user="%s\\%s" % (domain, username),
                password=password,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
        except ldap3.core.exceptions.LDAPBindError as e:
            if "strongerAuthRequired" in str(e):  # to handle ldap signing on port 389
                if DEBUG:
                    print("[%s] Trying to handle LDAP signing" % __name__)
                ldap_session = ldap3.Connection(
                    server=ldap_server,
                    user="%s\\%s" % (domain, username),
                    password=password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    session_security="ENCRYPT",
                )
            elif port == 636 and "invalidCredentials" in str(
                e
            ):  # to handle channel binding on port 636 (Exception is not different from truly invalid credentials...)
                if DEBUG:
                    print("[%s] Trying to handle channel binding" % __name__)
                ldap_session = ldap3.Connection(
                    server=ldap_server,
                    user="%s\\%s" % (domain, username),
                    password=password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                    channel_binding=ldap3.TLS_CHANNEL_BINDING,
                )
            else:
                raise

    if ldap_session is None:
        raise ldap3.core.exceptions.LDAPBindError("Failed to establish LDAP session")

    return ldap_server, ldap_session


def init_ldap_session(
    auth_domain,
    auth_dc_ip,
    auth_username,
    auth_password,
    auth_lm_hash,
    auth_nt_hash,
    auth_key=None,
    use_kerberos=False,
    kdcHost=None,
    use_ldaps=False,
):
    if use_kerberos:
        target_dc = kdcHost
    else:
        target_dc = auth_dc_ip if auth_dc_ip is not None else auth_domain

    if use_ldaps is True:
        try:
            return __init_ldap_connection(
                target=target_dc,
                tls_version=ssl.PROTOCOL_TLSv1_2,
                domain=auth_domain,
                username=auth_username,
                password=auth_password,
                lmhash=auth_lm_hash,
                nthash=auth_nt_hash,
                aesKey=auth_key,
                kdcHost=kdcHost,
                kerberos=use_kerberos,
            )
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return __init_ldap_connection(
                target=target_dc,
                tls_version=ssl.PROTOCOL_TLSv1,
                domain=auth_domain,
                username=auth_username,
                password=auth_password,
                lmhash=auth_lm_hash,
                nthash=auth_nt_hash,
                aesKey=auth_key,
                kdcHost=kdcHost,
                kerberos=use_kerberos,
            )
    else:
        return __init_ldap_connection(
            target=target_dc,
            tls_version=None,
            domain=auth_domain,
            username=auth_username,
            password=auth_password,
            lmhash=auth_lm_hash,
            nthash=auth_nt_hash,
            aesKey=auth_key,
            kdcHost=kdcHost,
            kerberos=use_kerberos,
        )


def raw_ldap_query(
    auth_domain,
    auth_dc_ip,
    auth_username,
    auth_password,
    auth_hashes,
    query,
    auth_key=None,
    attributes=["*"],
    searchbase=None,
    use_kerberos=False,
    kdcHost=None,
    use_ldaps=False,
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

    if searchbase is None:
        searchbase = ldap_server.info.other["defaultNamingContext"]

    ldapresults = list(
        ldap_session.extend.standard.paged_search(
            searchbase, query, attributes=attributes
        )
    )

    results = {}
    for entry in ldapresults:
        if entry["type"] != "searchResEntry":
            continue
        results[entry["dn"]] = entry["attributes"]

    return results
