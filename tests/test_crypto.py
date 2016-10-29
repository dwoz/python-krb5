from __future__ import unicode_literals
from binascii import unhexlify
from krb5.crypto import (
    _rotate_right, _add_ones_complement, _xorbytes, _SimplifiedEnctype,
    Key, Enctype, encrypt, decrypt, verify_checksum, Cksumtype, string_to_key, cf2, prf, _zeropad
)

def h(hexstr):
    return unhexlify(hexstr)

def test__rotate_right():
    a = _rotate_right(b'kerberos', 0)
    assert a == b'kerberos'

def test__add_ones_comlement():
    str1 = b'\x00\x00\x00\x01U\n\xa8\x00\x00\x00\x00\x00U@\x00\x00'
    str2 = b'\x00\x00\x02\xaa\x15P\x00\x00\x00\x00\x00\xaa\x80\x00\x00\x00'
    a = _add_ones_complement(str1, str2)
    assert a == b'\x00\x00\x02\xabjZ\xa8\x00\x00\x00\x00\xaa\xd5@\x00\x00'

def test__xorbytes_a():
    bytes1 = b'foo'
    bytes2 = b'bar'
    ret = _xorbytes(bytes1, bytes2)
    assert ret == b'\x04\x0e\x1d'

def test__xorbytes_b():
    bytes1 = b'8x\xd9:\x86\x05\x02F\x18\x15&d\xbc%}3'
    bytes2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    ret = _xorbytes(bytes1, bytes2)
    print(repr(ret))
    assert ret == b'8x\xd9:\x86\x05\x02F\x18\x15&d\xbc%}3'

def test_aes128_encdnc():
    # AES128 encrypt and decrypt
    kb = h(b'9062430C8CDA3388922E6D6A509F5B7A')
    conf = h(b'94B491F481485B9A0678CD3C4EA386AD')
    keyusage = 2
    plain = b'9 bytesss'
    ctxt = h(b'68FB9679601F45C78857B2BF820FD6E53ECA8D42FD4B1D7024A09205ABB7CD2E'
             b'C26C355D2F')
    k = Key(Enctype.AES128, kb)
    assert(encrypt(k, keyusage, plain, conf) == ctxt)
    assert(decrypt(k, keyusage, ctxt) == plain)


def test_aes256_encdnc():
    # AES256 encrypt and decrypt
    kb = h(b'F1C795E9248A09338D82C3F8D5B567040B0110736845041347235B1404231398')
    conf = h(b'E45CA518B42E266AD98E165E706FFB60')
    keyusage = 4
    plain = b'30 bytes bytes bytes bytes byt'
    ctxt = h(b'D1137A4D634CFECE924DBC3BF6790648BD5CFF7DE0E7B99460211D0DAEF3D79A'
             b'295C688858F3B34B9CBD6EEBAE81DAF6B734D4D498B6714F1C1D')
    k = Key(Enctype.AES256, kb)
    assert(encrypt(k, keyusage, plain, conf) == ctxt)
    assert(decrypt(k, keyusage, ctxt) == plain)

def test_aes128_checksum():
    # AES128 checksum
    kb = h(b'9062430C8CDA3388922E6D6A509F5B7A')
    keyusage = 3
    plain = b'eight nine ten eleven twelve thirteen'
    cksum = h(b'01A4B088D45628F6946614E3')
    k = Key(Enctype.AES128, kb)
    verify_checksum(Cksumtype.SHA1_AES128, k, keyusage, plain, cksum)

def test_aes256_checksum():
    # AES256 checksum
    kb = h(b'B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7')
    keyusage = 4
    plain = b'fourteen'
    cksum = h(b'E08739E3279E2903EC8E3836')
    k = Key(Enctype.AES256, kb)
    verify_checksum(Cksumtype.SHA1_AES256, k, keyusage, plain, cksum)

def test_aes128_string_to_key():
    # AES128 string-to-key
    string = b'password'
    salt = b'ATHENA.MIT.EDUraeburn'
    params = h(b'00000002')
    kb = h(b'C651BF29E2300AC27FA469D693BDDA13')
    k = string_to_key(Enctype.AES128, string, salt, params)
    assert(k.contents == kb)

def test_aes256_string_to_key():
    # AES256 string-to-key
    string = b'X' * 64
    salt = b'pass phrase equals block size'
    params = h(b'000004B0')
    kb = h(b'89ADEE3608DB8BC71F1BFBFE459486B05618B70CBAE22092534E56C553BA4B34')
    k = string_to_key(Enctype.AES256, string, salt, params)
    assert(k.contents == kb)

def test_aes128_prf():
    # AES128 prf
    kb = h(b'77B39A37A868920F2A51F9DD150C5717')
    k = string_to_key(Enctype.AES128, b'key1', b'key1')
    assert(prf(k, b'\x01\x61') == kb)

def test_aes256_prf():
    # AES256 prf
    kb = h(b'0D674DD0F9A6806525A4D92E828BD15A')
    k = string_to_key(Enctype.AES256, b'key2', b'key2')
    assert(prf(k, b'\x02\x62') == kb)

def test_aes128_cf2():
    # AES128 cf2
    kb = h(b'97DF97E4B798B29EB31ED7280287A92A')
    k1 = string_to_key(Enctype.AES128, b'key1', b'key1')
    k2 = string_to_key(Enctype.AES128, b'key2', b'key2')
    k = cf2(Enctype.AES128, k1, k2, b'a', b'b')
    assert(k.contents == kb)

def test_aes256_cf2():
    # AES256 cf2
    kb = h(b'4D6CA4E629785C1F01BAF55E2E548566B9617AE3A96868C337CB93B5E72B1C7B')
    k1 = string_to_key(Enctype.AES256, b'key1', b'key1')
    k2 = string_to_key(Enctype.AES256, b'key2', b'key2')
    k = cf2(Enctype.AES256, k1, k2, b'a', b'b')
    assert(k.contents == kb)

def test_des3_encdec():
    # DES3 encrypt and decrypt
    kb = h(b'0DD52094E0F41CECCB5BE510A764B35176E3981332F1E598')
    conf = h(b'94690A17B2DA3C9B')
    keyusage = 3
    plain = b'13 bytes byte'
    ctxt = h(b'839A17081ECBAFBCDC91B88C6955DD3C4514023CF177B77BF0D0177A16F705E8'
             b'49CB7781D76A316B193F8D30')
    k = Key(Enctype.DES3, kb)
    assert(encrypt(k, keyusage, plain, conf) == ctxt)
    assert(decrypt(k, keyusage, ctxt) == _zeropad(plain, 8))

def test_des3_str_to_key():
    # DES3 string-to-key
    string = b'password'
    salt = b'ATHENA.MIT.EDUraeburn'
    kb = h(b'850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E')
    k = string_to_key(Enctype.DES3, string, salt)
    assert(k.contents == kb)

def test_des3_checksum():
    # DES3 checksum
    kb = h(b'7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162')
    keyusage = 2
    plain = b'six seven'
    cksum = h(b'0EEFC9C3E049AABC1BA5C401677D9AB699082BB4')
    k = Key(Enctype.DES3, kb)
    verify_checksum(Cksumtype.SHA1_DES3, k, keyusage, plain, cksum)

def test_des3_cf2():
    # DES3 cf2
    kb = h(b'E58F9EB643862C13AD38E529313462A7F73E62834FE54A01')
    k1 = string_to_key(Enctype.DES3, b'key1', b'key1')
    k2 = string_to_key(Enctype.DES3, b'key2', b'key2')
    k = cf2(Enctype.DES3, k1, k2, b'a', b'b')
    assert(k.contents == kb)

def test_rc4_encdec():
    # RC4 encrypt and decrypt
    kb = h(b'68F263DB3FCE15D031C9EAB02D67107A')
    conf = h(b'37245E73A45FBF72')
    keyusage = 4
    plain = b'30 bytes bytes bytes bytes byt'
    ctxt = h(b'95F9047C3AD75891C2E9B04B16566DC8B6EB9CE4231AFB2542EF87A7B5A0F260'
             b'A99F0460508DE0CECC632D07C354124E46C5D2234EB8')
    k = Key(Enctype.RC4, kb)
    assert(encrypt(k, keyusage, plain, conf) == ctxt)
    assert(decrypt(k, keyusage, ctxt) == plain)

def test_rc4_str_to_key():
    # RC4 string-to-key
    string = b'foo'
    kb = h(b'AC8E657F83DF82BEEA5D43BDAF7800CC')
    k = string_to_key(Enctype.RC4, string, None)
    assert(k.contents == kb)

def test_rc4_checksum():
    # RC4 checksum
    kb = h(b'F7D3A155AF5E238A0B7A871A96BA2AB2')
    keyusage = 6
    plain = b'seventeen eighteen nineteen twenty'
    cksum = h(b'EB38CC97E2230F59DA4117DC5859D7EC')
    k = Key(Enctype.RC4, kb)
    verify_checksum(Cksumtype.HMAC_MD5, k, keyusage, plain, cksum)

def test_rc4_cf2():
    # RC4 cf2
    kb = h(b'24D7F6B6BAE4E5C00D2082C5EBAB3672')
    k1 = string_to_key(Enctype.RC4, b'key1', b'key1')
    k2 = string_to_key(Enctype.RC4, b'key2', b'key2')
    k = cf2(Enctype.RC4, k1, k2, b'a', b'b')
    assert(k.contents == kb)
