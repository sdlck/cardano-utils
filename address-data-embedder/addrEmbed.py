from mnemonic import Mnemonic
from hashlib import blake2b, sha512, sha3_256
from binascii import crc32
from base64 import standard_b64encode
from base58 import b58encode
from sys import argv
import os.path
import cbor
import hmac
import ed25519

def requestFile():
    fpath = input("Enter path to file: ")
    if os.path.isfile(fpath):
        with open(fpath, 'rb') as f:
            data = f.read()
    else:
        print("File not found at %s" % fpath)
        data = requestFile()
    return data

def requestData():
    ans = input("Embed text or file?: ").lower()
    if ans == 'text' or ans == 't':
        data = input("Enter text to embed: ")
        data = bytes(data.encode('utf-8'))
    elif ans == 'file' or ans == 'f':
        data = requestFile()
    else:
        print("%s is invalid.\nPlease enter 'text' or 'file'" % ans)
        data = requestData()
    return data

words = Mnemonic('english').generate(128)
data = requestData()

entropy = Mnemonic('english').to_entropy(words)
cborEnt = cbor.dumps(bytes(entropy))
seed = blake2b(cborEnt, digest_size=32)
cborSeed = cbor.dumps(seed.digest())

for i in range(1, 1000):
    buf = hmac.new(cborSeed, b'Root Seed Chain %d' % i, sha512).digest()
    buf_l, buf_r = buf[:32], buf[32:]
    root_xpriv = bytearray(sha512(buf_l).digest())
    root_xpriv[0] = root_xpriv[0] & 248
    root_xpriv[31] = root_xpriv[31] & 127
    root_xpriv[31] = root_xpriv[31] | 64
    if root_xpriv[31] & 32 == 0:
        bip32 = ed25519.SigningKey(buf_l)
        break
xpub = bip32.vk_s + buf_r

addrType = 0
data = cbor.dumps(data)
addrAttributes = {1: data}
addrRoot = [
        addrType,
        [ addrType, xpub ],
        addrAttributes
        ]
addrRoot = cbor.dumps(addrRoot, sort_keys=True)
sha3 = sha3_256(addrRoot)
addrRoot = blake2b(sha3.digest(), digest_size=28)
abstractHash = addrRoot.digest()
address = [
        abstractHash,
        addrAttributes,
        addrType
        ]
address = cbor.dumps(address)
crc = crc32(address)
taggedAddress = cbor.Tag(24, address)
cwid = cbor.dumps([taggedAddress, crc])
cwid = b58encode(cwid)

print("Mnemonic:", words)
print("Address: ", cwid.decode())
