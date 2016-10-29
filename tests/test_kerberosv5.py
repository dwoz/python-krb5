from krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
from krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from krb5 import constants
from krb5.types import Principal, KerberosTime, Ticket
from pyasn1.codec.der import decoder, encoder
import datetime
import os

import pytest

def test_getKerberosTGT():
    user = os.environ['KUSER']
    password = os.environ['KPASS']
    lmhash = ''
    nthash = ''
    aesKey = ''
    kdcHost = 'fxdc0004.filex.com'
    domain = 'FILEX.COM'
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    print(tgt)

