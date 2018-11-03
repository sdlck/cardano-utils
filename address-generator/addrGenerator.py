from mnemonic import Mnemonic
import hashlib
import cbor
import binascii
import scrypt
import base64
import sys
import hmac
import ed25519
import base58

words = sys.argv[1]
print("\nMnemonic:", words)

entropy = Mnemonic('english').to_entropy(words)
print("Entropy:", entropy.hex())

cborEnt = cbor.dumps(bytes(entropy))
print("Serialised:", cborEnt.hex(), "\n")

seed = hashlib.blake2b(cborEnt, digest_size=32)
print("Seed:", seed.hexdigest())

cborSeed = cbor.dumps(seed.digest())
print("Serialised:", cborSeed.hex(), "\n")

passPhrase = sys.argv[2]
print("Spending pass:", passPhrase)

passPhrase = cbor.dumps(passPhrase.encode())
print("Serialised:", passPhrase.hex())

seedBuf = cbor.dumps(cborSeed)

hashedSeed = hashlib.blake2b(seedBuf, digest_size=32)
salt = cbor.dumps(hashedSeed.digest())
print("Salt:", salt.hex())

hashedPass = scrypt.hash(passPhrase, salt, buflen=32)
print("Pass:", hashedPass.hex())

encryptedPass = "14|8|1|" + base64.standard_b64encode(hashedPass).decode() + "|" + base64.standard_b64encode(salt).decode()
encryptedPass = cbor.dumps(encryptedPass.encode('utf-8'))
print("Encrypted Pass:", encryptedPass.decode())
print("Base64-ed:", base64.standard_b64encode(encryptedPass).decode(), "\n")

for i in range(1, 1000):
    buf = hmac.new(cborSeed, b'Root Seed Chain %d' % i, hashlib.sha512).digest()
    buf_l, buf_r = buf[:32], buf[32:]
    bip32 = ed25519.SigningKey(buf_l)
    if bip32:
        break

print("SecretKey:", buf_l.hex())
print("ChainCode:", buf_r.hex())

xpub = bip32.vk_s + buf_r
print("XPub:", xpub.hex())

addrType = 0
addrAttributes = {}
addrRoot = [
        addrType,
        [ addrType, xpub ],
        addrAttributes
        ]

addrRoot = cbor.dumps(addrRoot)
print("addrRoot:", addrRoot.hex())

sha3 = hashlib.sha3_256(addrRoot)
print("SHA3:", sha3.hexdigest())

addrRoot = hashlib.blake2b(sha3.digest(), digest_size=28)
print("Blake2b:", addrRoot.hexdigest())

abstractHash = addrRoot.digest()
address = [
        abstractHash,
        addrAttributes,
        addrType
        ]
address = cbor.dumps(address)
crc = binascii.crc32(address)
taggedAddress = cbor.Tag(24, address)
cwid = cbor.dumps([taggedAddress, crc])
cwid = base58.b58encode(cwid)
print("CwID:", cwid.decode(), "\n")
