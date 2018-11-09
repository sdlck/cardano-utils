from binascii import crc32
from base58 import b58encode
from sys import argv
import os
import cbor

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

data = cbor.dumps(requestData())
address = [
        b'0000000000000000000000000000',
        {1: data},
        0
        ]
address = cbor.dumps(address)
crc = crc32(address)
taggedAddress = cbor.Tag(24, address)
cwid = cbor.dumps([taggedAddress, crc])
size = len(cwid)
cwid = b58encode(cwid)

a = 0.155381
b = 0.000043946
estFees = a + b * size

print("Address:", cwid.decode())
print("Address Size (bytes):", size)
print("Est. fees:", estFees, "ADA")
