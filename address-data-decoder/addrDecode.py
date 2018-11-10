from sys import argv
from base58 import b58decode
import cbor
import binascii
import enchant
import filetype

addr = argv[1]
d = enchant.Dict('en_US')

def lookForText(data):
    try:
        words = data.decode().split(' ')
        for word in words:
            if word != '':
                if d.check(word) == True:
                    return True
        return False
    except:
        return False

def lookForFile(data):
    kind = filetype.guess(data)
    if kind is None:
        return False
    return kind

def searchAddr(addr):
    unpackedAddr = cbor.loads(cbor.loads(b58decode(addr))[0].value)
    abstractHash = unpackedAddr[0]
    addrAttributes = unpackedAddr[1]

    if addrAttributes != {}:
        addrAttributes = cbor.loads(addrAttributes[1])

    try:
        addrAttributes = binascii.unhexlify(addrAttributes)
    except:
        pass

    hashText = lookForText(abstractHash)
    attrText = lookForText(addrAttributes)
    attrFile = lookForFile(addrAttributes)

    if hashText:
        print("\nText found in hash:\n")
        print(abstractHash.decode(), "\n")

    if attrText:
        print("\nText found in attributes:\n")
        print(addrAttributes.decode(), "\n")

    if attrFile != False:
        print("\n%s file found in attributes:\n" % attrFile.mime)
        print("Writing to %s.%s\n" % (addr[:6], attrFile.extension))
        with open('%s.%s' % (addr[:6], attrFile.extension), 'wb') as f:
            f.write(addrAttributes)
        attrFile = True

    if not hashText | attrText | attrFile:
        print("\nNothing found\n")

searchAddr(addr)
