#!/usr/bin/python
from binascii import hexlify, unhexlify
from simpybtc.bci import make_request
from simpybtc.main import *    #https://gist.github.com/anonymous/17b0bad3aa926609096a


# get the 2048 word wordlist
try:
    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    try:
        BIP39WORDS = make_request(
            "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt").decode('utf-8').split('\n')
        assert len(BIP39WORDS) == 2048
    except:
        fo = open('bip39_english.txt', 'r')
        f = fo.readlines()
        f = map(lambda x: str(x).replace('\n',''), f)
        f.pop(-1) if f[-1] == '' else None
        BIP39WORDS = f[:]
        assert len(BIP39WORDS) == 2048

except:
    raise IOError("Cannot get BIP39 word list")

def bip39_hex_to_mnemonic(hexv):
    """
    Convert hex seed to mnemonic representation (BIP39)
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    Essentially converts hex value to binary (with appended checksum),
    and splits into 11-bit binary chunks, each indexing a 2048 (=2**11)
    word list (in BIP39WORDS)

    hexseed: hexadecimal bytes or bytearray object

    >>> bip39_hex_to_mnemonic(b'eaebabb2383351fd31d703840b32e9e2')
    'turtle front uncle idea crush write shrug there lottery flower risk shell'
    """

    if isinstance(hexv, (bytes, str)) and re.match('^[0-9a-fA-F]*$', hexv):
        hexv = from_string_to_bytes(hexv)
    else:
        raise TypeError("Enter a hex seed!")

    if len(hexv) % 4 != 0:
        raise Exception("Value not a multiple of 4 bytes!")
    elif len(hexv) not in range(4, 125, 4):
        raise Exception("32 < entropy < 992 bits only!")

    hexv = unhexlify(hexv)
    cs = hashlib.sha256(hexv).hexdigest() # sha256 hexdigest
    bstr = changebase( binascii.hexlify(hexv), 16, 2, len(hexv) * 8) + \
		   changebase( cs, 16, 2, 256)[ : len(hexv) * 8 // 32]

    return " ".join( [BIP39WORDS[int(x, 2)] for x in
                      [bstr[i:i+11] for i in range(0, len(bstr), 11)] ] )

def bip39_mnemonic_to_seed(mnemonic, saltpass='mnemonic'):
    """
    Convert BIP39 mnemonic phrase to hex seed (bytes)
    See BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    mnemonic: single spaced, lower-case words (bytes/bytearray object)

    >>>bip39_mnemonic_to_seed(b"board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    """

    if isinstance(mnemonic, string_types):
        try:
            mn_array = from_string_to_bytes(mnemonic).lower().strip().split(" ")
        except:
            raise TypeError("Enter a lower case, single-spaced mnemonic!")
    else:   raise TypeError("Enter a lower case, single-spaced mnemonic!!")

    if len(mn_array) not in range(3, 124, 3):
        raise TypeError("32 < entropy < 992 bits; Input too big or too small")
    if len(mn_array) % 3 != 0:
        raise TypeError("Too many or too few words")
    #assert all(map(lambda x: x in BIP39WORDS, mnemonic_array)) # check all words are in list
    mnem = ' '.join(mn_array)

    try:
        assert bip39_check_mnemonic(mnem)
        seed = pbkdf2(mnem, 'mnemonic'+saltpass)
        return hexlify(seed)
    except:
        raise IOError("Mnemonic checksum is bad!")

def bip39_check_mnemonic(mnemonic):
    """
    Assert mnemonic is BIP39 standard
    """
    if isinstance(mnemonic, string_types):
        try:
            mn_array = from_string_to_bytes(mnemonic).lower().strip().split(" ")
        except:
            raise TypeError("Enter a lower case, single-spaced mnemonic!")
    else:   raise TypeError("Enter a lower case, single-spaced mnemonic!!")

    if len(mn_array) not in range(3, 124, 3):
        raise TypeError("32 < entropy < 992 bits; Input too big or too small")
    if len(mn_array) % 3 != 0:
        raise TypeError("Too many or too few words")
    assert all(map(lambda x: x in BIP39WORDS, mn_array)) # check all words are in list

    try:    binstr = ''.join([ changebase(str(BIP39WORDS.index(x)), 10, 2, 11) for x in mn_array])
    except: raise IOError("Are the words in the right order?")

    L = len(binstr)
    bd = binstr[:L // 33 * 32]
    cs = binstr[-L // 33:]
    hexd = unhexlify(changebase(bd, 2, 16, L // 33 * 8))
    hexd_cs = changebase(hashlib.sha256(hexd).hexdigest(), 16, 2, 256)[:L // 33]
    return cs == hexd_cs

def bip39_generate(bits=128):
    """Generates a tuple of (hex seed, mnemonic)"""
    if bits % 32:
        raise Exception('Should be divisible by 32, but is .. %d' % bits)
    data = hexlify(random_string(bits // 8))
    return (data, bip39_hex_to_mnemonic(data))

