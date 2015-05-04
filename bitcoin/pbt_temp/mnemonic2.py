#!/usr/bin/python
from binascii import hexlify, unhexlify
from bitcoin.bci import *    # pybitcointools library, importing URL grabber
from bitcoin.main import *   # pybitcointools library...
                             # combined functions @
                    # https://gist.github.com/anonymous/17b0bad3aa926609096a

# get the 2048 word wordlist
try:
    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    try:
        global BIP39WORDS
        BIP39WORDS = make_request("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt").decode('utf-8').split('\n')
        assert len(BIP39WORDS) == 2048
    except:
        pass
except:
    raise IOError("Cannot get BIP39 word list")

def bip39_seed_to_mnemonic(hexseed):
    """
    Convert hex seed to mnemonic representation (BIP39)
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    Essentially converts hex value to binary (with appended checksum),
    and splits into 11-bit binary chunks, each indexing a 2048 (=2**11)
    word list (in BIP39WORDS)

    hexseed: hexadecimal bytes or bytearray object

    >>> bip39_seed_to_mnemonic(b'eaebabb2383351fd31d703840b32e9e2')
    'turtle front uncle idea crush write shrug there lottery flower risk shell'
    """

    if isinstance(hexseed, (bytes, str)) and re.match('^[0-9a-fA-F]*$', from_bytes_to_string(hexseed)):
        hexseed = from_string_to_bytes(hexseed)
    else:
        raise TypeError("Enter a hex seed!")

    hexseed = unhexlify(hexseed)
    hexbin = changebase( hexlify(hexseed), 16, 2, len(hexseed)*8)

    if len(hexseed) % 4 != 0:
        raise Exception("Seed not a multiple of 4 bytes!")
    elif len(hexseed) < 4:
        raise Exception("Seed must be at least 32 bits of entropy")
    elif len(hexseed) > 124:
        raise Exception("Seed cannot exceed 992 bits of entropy")

    checksum_length = (len(hexseed) * 8) // 32
    checksum = hashlib.sha256(hexseed).hexdigest() # sha256 hexdigest
    checksum_bin = changebase(
          checksum, 16, 2, len(unhexlify(checksum))*8)

    binstr_final = from_string_to_bytes(
                 str(hexbin) + str(checksum_bin)[:checksum_length])
    binlist_words = [binstr_final[i:i+11] for i in
                 range(0, len(binstr_final), 11)]

    return " ".join( [BIP39WORDS[int(x, 2)] for x in binlist_words ] )

def bip39_mnemonic_to_seed(mnemonic):
    """
    Convert BIP39 mnemonic phrase to hex seed (bytes)
    See BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    mnemonic: single spaced, lower-case words (bytes/bytearray object)

    >>>bip39_mnemonic_to_hex(b"board flee heavy tunnel powder denial science ski answer betray cargo cat")
    '18ab19a9f54a9274f03e5209a2ac8a91'
    """

    if isinstance(mnemonic, string_types):
        mnemonic = from_bytes_to_string(mnemonic).lower().strip()
    else:
        raise TypeError("Enter a lower case, single-spaced mnemonic!")

    try:
        mnemonic_array = str(mnemonic).split(" ")
        if mnemonic_array[0] is '': mnemonic_array.pop(0)
    except:
        raise TypeError("Enter a lower case, single-spaced mnemonic!")

    if not (93 > len(mnemonic_array) > 3):
        raise TypeError("32 < entropy < 992 bits; Input too big or too small")
    if len(mnemonic_array) % 3 != 0:
        raise TypeError("Too many or too few words")
    #assert all(map(lambda x: x in BIP39WORDS, mnemonic_array)) # check all words are in list

    binstr = ''.join([ changebase(str(BIP39WORDS.index(x)), 10, 2, 11) for x in mnemonic_array])
    num_checksum_digits = len(binstr) % 32

    binary_checksum = binstr[(len(binstr) - num_checksum_digits):]
    binary_no_checksum = binstr[ : (-1*num_checksum_digits)]

    hexoutput = hexlify(changebase(binary_no_checksum, 2, 16,
    len(binary_checksum) * 8))
    assert not (len(hexoutput) % 2)
    checksum_bin = changebase(hashlib.sha256(
                       unhexlify(hexoutput)).hexdigest(), 16, 2, 256)

    assert checksum_bin[:int(num_checksum_digits)] != binary_checksum
    return unhexlify(hexoutput)

