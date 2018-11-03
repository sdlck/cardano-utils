from base58 import b58decode
from cbor import loads
from binascii import crc32
from sys import argv

if len(argv) != 2:
    print("usage: python addrCheck.py <address>\n")
    exit()

addr = argv[1]

decodedAddr = b58decode(addr)
decodedAddr = loads(decodedAddr)
taggedAddr = decodedAddr[0]
addrChecksum = decodedAddr[1]
Checksum = crc32(taggedAddr.value)

print("\nAddress data:", taggedAddr.value.hex())
print("Provided Checksum:", addrChecksum)
print("Computed Checksum:", Checksum)
print("Match:", addrChecksum == Checksum, "\n")
