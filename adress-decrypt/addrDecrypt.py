from mnemonic import Mnemonic
from hashlib import blake2b, sha512
from base58 import b58decode
from pbkdf2 import PBKDF2
from chacha20poly1305 import ChaCha20Poly1305
from sys import argv
import cbor
import hmac
import ed25519

words = argv[1]
addr = argv[2]

entropy = Mnemonic('english').to_entropy(words)
cborEnt = cbor.dumps(bytes(entropy))
seed = blake2b(cborEnt, digest_size=32)
cborSeed = cbor.dumps(seed.digest())

for i in range(5, 1000):
    buf = hmac.new(cborSeed, b'Root Seed Chain %d' % i, sha512).digest()
    buf_l, buf_r = buf[:32], buf[32:]
    if sha512(buf_l).digest()[31] & 32 == 0:
        bip32 = ed25519.SigningKey(buf_l)
        break


xpub = bip32.vk_s + buf_r

decodedAddr = b58decode(addr)
loadedAddr = cbor.loads(decodedAddr)
address = cbor.loads(loadedAddr[0].value)
addrAttributes = cbor.loads(address[1][1])

nonce = b'serokellfore'
hdpass = PBKDF2(xpub, 'address-hashing', iterations=500, digestmodule=sha512).read(32)
cip = ChaCha20Poly1305(hdpass)
decryptedAttr = cip.decrypt(nonce, addrAttributes)
decryptedAttr = cbor.loads(decryptedAttr)

print("Decrypted data:", decryptedAttr)
