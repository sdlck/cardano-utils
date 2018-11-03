import base58
import cbor
import sys

addr = sys.argv[1]

decodedAddr = cbor.loads(base58.b58decode(addr))
Checksum = decodedAddr[1]
unpackedAddr = cbor.loads(decodedAddr[0].value)
abstractHash = unpackedAddr[0]
addrAttributes = unpackedAddr[1]
addrType = unpackedAddr[2]

if addrAttributes != {}:
    addrAttributes = cbor.loads(addrAttributes[1]).hex()

print("\nAbstract Hash:", abstractHash.hex())
print("Attributes:", addrAttributes)
print("Type:", addrType)
print("Checksum:", Checksum, "\n")
