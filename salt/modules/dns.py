# -*- coding: utf-8 -*-
'''
Compendium of DNS utilitiese

# Local stuff to resolv.py
resolv()
resolv_dostuff()
hosts()
hosts_dostuff()


'''

# Python libs

# Salt libs
import salt.utils.dns
import salt.utils.validate.net

# logging & debugging
import logging
import pprint

ppr = pprint.PrettyPrinter(indent=2).pprint

log = logging.getLogger(__name__)


def __virtual__():
    return True


def _resolve(host, **kwargs):
    if isinstance(host, (list, tuple)):
        res = {}
        for h in host:
            hres = _resolve(h, **kwargs)
            if not hres:
                continue
            for k, v in hres.items():
                res[k] = res.get(k, []).extend(v)
        return res
    else:
        res = {}
        if salt.utils.validate.net.ipv4_addr(host):
            res['ip4'] = [host]
        elif salt.utils.validate.net.ipv6_addr(host):
            res['ip6'] = [host]
        else:
            res = host(host, **kwargs)
        return res


def lookup(
    name,
    rdtype,
    servers=None,
    timeout=None,
    walk=False,
    secure=None,
    raw=False,
):
    '''
    Perform DNS lookups.
    Lookups are fast for simple addresses and when dnspython is installed.
    In other cases an external binary (dig, drill, host, nslookup) will be called.

    :param name:
        name to lookup

    :param rdtype:
        DNS record type

    :param servers:
        Server or list of overriding nameservers to use.

    :param timeout:
        Query timeout. Or a valiant approximation of that.

    :param walk:
        If the domain does not contain the record, try the parent domain(s).

    :param secure:
        Return only DNSSEC secured responses

    :param raw:
        Return only the record data

    :return: [] of records or their data, False on error or None if no records exist.


    CLI Example:

    .. code-block:: bash

        salt ns1 dns.lookup www.saltstack.com AAAA
        salt ns1 dns.lookup saltstack.com SPF raw=True
        salt ns1 dns.lookup repo.saltstack.com timeout=8
        salt ns1 dns.lookup wpad rdtype=AAAA walk=True
    '''
    if raw:
        dns_q = salt.utils.dns.lookup
    else:
        dns_q = salt.utils.dns.query

    res = dns_q(
        name, rdtype,
        servers=servers,
        timeout=timeout,
        walk=walk,
        secure=secure,
        method='auto',
        walk_tld=False
    )
    return res


def host(name, ip6=True, ip4=True, **kwargs):
    '''
    Return a list of addresses for name

    :param ip6:
        Include list of IPv6 addresses
    :param ip4:
        Include list of IPv4 addresses

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.host saltstack.com
    '''
    return salt.utils.dns.host(name, ip6, ip4, **kwargs)


def A(host, **kwargs):
    '''
    Return the IPv4 addresses of a host

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.A saltstack.com
    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')

    return lookup(host, 'A', **kwargs)


def AAAA(host, **kwargs):
    '''
    Return the IPv6 addresses of a host
    CLI Example:

    .. code-block:: bash

        salt ns1 dns.AAAA saltstack.com

    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')

    return lookup(host, 'AAAA', **kwargs)


def CAA(domain, **kwargs):
    '''
    Return the authorized Certificate Authorities of the domain.

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.CAA saltstack.com
    '''
    return lookup(domain, 'CAA', **kwargs)


def MX(domain, resolve=False, **kwargs):
    '''
    Return the mail transfer agents of the domain

    :param resolve:
        Resolve the names of the agents to IP addresses

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.MX saltstack.com
    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')

    res = lookup(domain, 'MX', **kwargs)

    if not resolve or not res:
        return res

    for pref, agents in res.items():
        res[pref] = _resolve(agents, **kwargs)

    return res


def NS(domain, resolve=False, **kwargs):
    '''
    Return the nameservers for the domain.

    :param resolve:
        Resolve names of the servers to IP addresses

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.NS saltstack.com resolve=True
    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')

    res = lookup(domain, 'NS', **kwargs)
    if not resolve or not res:
        return res
    else:
        return _resolve(res, **kwargs)


def PTR(ip, **kwargs):
    '''
    Return the pointer for an IP address.

    If raw=True you must provide the actual record name, e.g. 1.168.192.in-addr.arpa

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.PTR 104.197.168.128 resolve=True

    '''
    return lookup(ip, 'PTR', **kwargs)


def SOA(domain, **kwargs):
    '''
    Return the DNS authority record for the domain.

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.SOA saltstack.com
    '''
    return lookup(domain, 'SOA', **kwargs)


def SPF(domain, **kwargs):
    '''
    Return the authorized mail senders for the domain.
    The SPF record is deprecated, so unless raw=True, SPF data in TXT records will be looked up first

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.SPF saltstack.com
    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')
    return lookup(domain, 'SPF', **kwargs)


def SRV(service, proto='tcp', domain=None, **kwargs):
    name = salt.utils.dns.srv_name(service, proto, domain)
    return lookup(name, 'SRV', **kwargs)


def SSHFP(host, **kwargs):
    '''
    Return the SSH fingerprints of a host.
    Just like SSH itself, this defaults to secure=True

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.SSHFP builder1.saltstack.com
        salt ns1 dns.SSHFP builder1.saltstack.com secure=False
    '''
    return lookup(host, 'SSHFP', secure=True, **kwargs)


def TLSA(service, **kwargs):
    '''
    Return DNS-authorized certificates for a service

    '''
    return lookup(service, 'TLSA', **kwargs)


def TXT(name, **kwargs):
    '''
    Return the text records for ``name``.

    CLI Example:

    .. code-block:: bash

        salt ns1 dns.TXT saltstack.com
    '''
    if 'nameserver' in kwargs:
        salt.utils.versions.warn_until(
            'Natrium',
            'The \'nameserver\' argument has been deprecated and will be removed in Salt {version}.'
            'Please use \'servers\' instead.'
        )
        kwargs['servers'] = kwargs.pop('nameserver')

    return lookup(name, 'TXT', **kwargs)


# Let lowercase work, since that is the convention for Salt functions
a = A
aaaa = AAAA
caa = CAA
mx = MX
ns = NS
ptr = PTR
spf = SPF
sshfp = SSHFP
soa = SOA
srv = SRV
tlsa = TLSA
txt = TXT
