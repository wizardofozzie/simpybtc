def pbkdf_two(passwd, salt, iters=2048, keylen=64, digestmod=hashlib.sha512):
    """
    >>> hexlify(pbkdf2(b'All n-entities must communicate with other n-entities via n-1 entiteeheehees', unhexlify('1234567878563412'), 500, 16, hashlib.sha1))
    '6a8970bf68c92caea84a8df285108586'
    """
    dgsz = digestmod().digest_size if callable(digestmod) else digestmod.digest_size
    if keylen is None: keylen = dgsz
    # Helper function which copies each iteration for h, where h is an hmac seeded with password
    def pbhelper(h, salt, itercount, blocksize):
        def prf(h, data):
            hm = h.copy()
            hm.update(data)
            return hm.digest()
        U = prf(h, salt + struct.pack('>i', blocksize))
        T = U
        for j in range(2, itercount+1):
            U = prf(h, U)
            T = "".join([chr( ord(x) ^ ord(y) ) for (x, y) in zip( T, U )]) \
                  if is_python2 else bytes([x ^ y for (x, y) in zip(T, U)])    # XORing
        return T
    L = int(keylen/dgsz) # L - number of output blocks to produce
    if keylen % dgsz != 0: L += 1
    h = hmac.new(key=passwd, msg=None, digestmod=digestmod )
    T = b""
    for i in range(1, L+1):
        T += pbhelper(h, salt, iters, i)
    return T[:keylen]
    
def pbkdf2(password, salt, iters, keylen, digestmod):
    """Run the PBKDF2 (Password-Based Key Derivation Function 2) algorithm
    and return the derived key. The arguments are:
 
    password (bytes or bytearray) -- the input password
    salt (bytes or bytearray) -- a cryptographic salt
    iters (int) -- number of iterations
    keylen (int) -- length of key to derive
    digestmod -- a cryptographic hash function: either a module
        supporting PEP 247, a hashlib constructor, or (in Python 3.4
        or later) the name of a hash function.
 
    For example:
 
    >>> import hashlib
    >>> from binascii import hexlify, unhexlify
    >>> password = b'Squeamish Ossifrage'
    >>> salt = unhexlify(b'1234567878563412')
    >>> hexlify(pbkdf2(password, salt, 500, 16, hashlib.sha1))
    b'9e8f1072bdf5ef042bd988c7da83e43b'
 
    """
    h = hmac.new(password, digestmod=digestmod)
    def prf(data):
        hm = h.copy()
        hm.update(data)
        return bytearray(hm.digest())
 
    key = bytearray()
    i = 1
    while len(key) < keylen:
        T = U = prf(salt + struct.pack('>i', i))
        for _ in range(iters - 1):
            U = prf(U)
            T = bytearray(x ^ y for x, y in zip(T, U))
        key += T
        i += 1
 
    return key[:keylen]