import Rsa as rsa
import hashlib
import random


def get_str_sha1_secret_str(res):
    """
    使用sha1加密算法，返回bytes加密后的hex字符串
    """
    sha = hashlib.sha1(res)
    encrypts = sha.hexdigest()
    return encrypts


def encode(n, e, m, l=b''):
    n_hex = hex(n)[2:]
    if len(n_hex) & 1 == 1:
        n_hex = '0' + n_hex
    # m:bytes
    em = oeap_encode(n, e, m, l)
    c = rsa.encode(n, e, int(em, 16))
    k = len(n_hex) // 2
    res = "%0*x" % (k * 2, c)
    return bytearray.fromhex(res)


def decode(key, k_flag, c, l=b''):
    if k_flag == 1:
        n = key[0] * key[1]
    else:
        n = key[0]
    n_hex = hex(n)[2:]
    if len(n_hex) & 1 == 1:
        n_hex = '0' + n_hex

    k = len(n_hex) // 2
    hLen = 20
    if len(c) != k or (k < 2 * hLen + 2):
        return 'Wrong c!\n'
    cc = int(c.hex(), 16)
    if k_flag:
        em = rsa.decode2(key[0], key[1], key[2], key[3], key[4], cc)
    else:
        em = rsa.decode1(key[0], key[1], cc)
    EM = '%0*x' % (k * 2, em)
    return oeap_decode(EM, k, hLen, l)


def oeap_encode(n, e, m, l=b''):
    n_hex = hex(n)[2:]
    if len(n_hex) & 1 == 1:
        n_hex = '0' + n_hex
    k = len(n_hex) // 2
    hLen = 20
    mLen = len(m)
    if mLen > (k - 2 - 2 * hLen):
        return 'Too long message!\n'

    lhash = get_str_sha1_secret_str(l)
    if (k - mLen - 2 * hLen - 2) > 0:
        ps = '00' * (k - mLen - 2 * hLen - 2) + '01'
    else:
        ps = '01'
    DB = lhash + ps + m.hex()
    seed = g_seed(hLen)
    dbMask = MGF(seed, k - hLen - 1, hLen)
    maskedDB = hex_xor(dbMask, DB, (k - hLen - 1) * 2)
    seedMask = MGF(maskedDB, hLen, hLen)
    maskedSeed = hex_xor(seed, seedMask, hLen * 2)
    EM = '00' + maskedSeed + maskedDB
    return EM


def oeap_decode(EM, k, hLen, l=b''):
    lhash = get_str_sha1_secret_str(l)
    Y = EM[:2]
    if Y != '00':
        return 'Wrong Y!\n'
    maskedSeed = EM[:2 + 2 * hLen]
    maskedDB = EM[2 + 2 * hLen:]
    seedMask = MGF(maskedDB, hLen, hLen)
    seed = hex_xor(seedMask, maskedSeed, 2 * hLen)
    dbMask = MGF(seed, k - hLen - 1, hLen)
    DB = hex_xor(dbMask, maskedDB, (k - hLen - 1) * 2)
    index = 2 * hLen
    llhash = DB[:index]
    if lhash != llhash:
        return bytes('Wrong hash!\n').hex()
    while DB[index:index + 2] == '00':
        index += 2
    if DB[index:index + 2] != '01':
        return bytes('Wrong PS!\n').hex()
    index = index + 2
    m = DB[index:]
    return bytearray.fromhex(m)


def MGF(x, maskLen, hLen):
    T = bytearray(b'')
    k = maskLen // hLen
    if len(x) & 1 == 1:
        x = '0' + x
    X = bytearray.fromhex(x)
    if maskLen % hLen == 0:
        k -= 1
    for i in range(k + 1):
        tmp = X + bytearray.fromhex('%08x' % i)
        T = T + bytearray.fromhex(get_str_sha1_secret_str(tmp))
    mask = T[:maskLen]
    return mask.hex()


def g_seed(hLen):
    b = bytearray(hLen)
    for i in range(hLen):
        b[i] = random.randint(0, 255)
    return b.hex()


def hex_xor(a, b, l):
    return "%0*x" % (l, int(a, 16) ^ int(b, 16))