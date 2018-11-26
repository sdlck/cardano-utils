const bigNumber = require('bignumber.js')
const bs58 = require('bs58')
const bip39 = require('bip39')
const blake = require('blakejs')
const crypto = require('crypto')
const sha3_256 = require('js-sha3').sha3_256;
const cbor = require('cbor')
const CRC = require('crc')
const ed25519 = require('ed25519')
const pbkdf2 = require('pbkdf2')
const EdDsa = require('elliptic-cardano').eddsaVariant
const ec = new EdDsa('ed25519')
const chacha20 = require('@stablelib/chacha20poly1305')


// Get mnemonic words from input
words = process.argv[2]
console.log("\nMnemonic:", words)

// Derive seed from mnemonic
entropy = bip39.mnemonicToEntropy(words)
serializedEnt = cbor.encode(Buffer.from(entropy, 'hex'))
seed = blake.blake2b(serializedEnt, null, 32)
serializedSeed = cbor.encode(Buffer.from(seed))

// Derive root keys
for (const i of Array(10).keys()) {
        phrase = "Root Seed Chain " + (i + 1)
        hmac = crypto.createHmac('sha512', serializedSeed)
        hmac.update(phrase)
        buf = hmac.digest()
        buf_l = buf.slice(0, 32)
        buf_r = buf.slice(32, 64)

        root_xpriv = crypto.createHash('sha512')
        root_xpriv.update(buf_l)
        root_xpriv = root_xpriv.digest()
        root_xpriv[0] &= 248
        root_xpriv[31] &= 127
        root_xpriv[31] |= 64

        if ((root_xpriv[31] & 32) == 0) {
                bip32 = ed25519.MakeKeypair(buf_l)
                break;
        }
}

root_xpub = Buffer.concat([bip32.publicKey, buf_r])
root_xpriv = Buffer.concat([root_xpriv, root_xpub])
console.log("\nExtended Root Private Key:", root_xpriv.toString('hex'))

// Construct Cardano Wallet ID
addrType = 0
addrAttributes = {}
addrRoot = [
        addrType,
        [ addrType, root_xpub ],
        addrAttributes
]
serializedAddrRoot = cbor.encode(addrRoot)
sha3AddrRoot = sha3_256(serializedAddrRoot)
abstractHash = blake.blake2b(Buffer.from(sha3AddrRoot, 'hex'), null, 28)
address = cbor.encode([
        Buffer.from(abstractHash),
        addrAttributes,
        addrType
])
checksum = CRC.crc32(address)
taggedAddr = new cbor.Tagged(24, address)
CWID = cbor.encode([taggedAddr, checksum])
CWID = bs58.encode(CWID)
console.log("\nCWID:", CWID)

// Define required functions 
// from https://github.com/vacuumlabs/adalite/blob/4de87a15e9a768b9ef960779ccd46095dfcc9090/wallet/address.js
function add256NoCarry(b1, b2) {
  let result = ''

  for (let i = 0; i < 32; i++) {
    result += ((b1[i] + b2[i]) & 0xff).toString(16).padStart(2, '0')
  }

  return Buffer.from(result, 'hex')
}

function toLittleEndian(str) {
  // from https://stackoverflow.com/questions/7946094/swap-endianness-javascript
  const s = str.replace(/^(.(..)*)$/, '0$1') // add a leading zero if needed
  const a = s.match(/../g) // split number in groups of two
  a.reverse() // reverse the goups
  return a.join('') // join the groups back together
}

function scalarAdd256ModM(b1, b2) {
  let resultAsHexString = bigNumber(toLittleEndian(b1.toString('hex')), 16)
    .plus(bigNumber(toLittleEndian(b2.toString('hex')), 16))
    .mod(bigNumber('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16))
    .toString(16)
  resultAsHexString = toLittleEndian(resultAsHexString).padEnd(64, '0')

  return Buffer.from(resultAsHexString, 'hex')
}

function multiply8(buf) {
  let result = ''
  let prevAcc = 0

  for (let i = 0; i < buf.length; i++) {
    result += ((((buf[i] * 8) & 0xff) + (prevAcc & 0x8)) & 0xff).toString(16).padStart(2, '0')
    prevAcc = buf[i] * 32
  }

  return Buffer.from(result, 'hex')
}

class CborIndefiniteLengthArray {
  constructor(elements) {
    this.elements = elements
  }

  encodeCBOR(encoder) {
    return encoder.push(
      Buffer.concat([
        Buffer.from([0x9f]), // indefinite array prefix
        ...this.elements.map((e) => cbor.encode(e)),
        Buffer.from([0xff]), // end of array
      ])
    )
  }
}

function derivePrivateKey(xpriv, index) {
        chainCode = xpriv.slice(96, 128)
        secretKey = xpriv.slice(0, 64)

        hmac1 = crypto.createHmac('sha512', chainCode)
        hmac1.update(Buffer.from([0x00]))
        hmac1.update(secretKey)
        hmac1.update(Buffer.from(index.toString(16).padStart(8, '0'), 'hex'))

        z = Buffer.from(hmac1.digest('hex'), 'hex')
        zl8 = multiply8(z, Buffer.from([0x08])).slice(0, 32)
        kl = scalarAdd256ModM(zl8, xpriv.slice(0, 32))
        kr = add256NoCarry(z.slice(32, 64), xpriv.slice(32, 64))
        resKey = Buffer.concat([kl, kr])

        hmac2 = crypto.createHmac('sha512', chainCode)
        hmac2.update(Buffer.from([0x01]))
        hmac2.update(secretKey)
        hmac2.update(Buffer.from(index.toString(16).padStart(8, '0'), 'hex'))

        newChainCode = Buffer.from(hmac2.digest('hex').slice(64, 128), 'hex')
        newPublicKey = Buffer.from(ec.keyFromSecret(resKey.toString('hex').slice(0, 64)).getPublic('hex'), 'hex')

        new_xpriv = Buffer.concat([resKey, newPublicKey, newChainCode])

        return new_xpriv
}

function deriveChildPrivate(xpriv, path) {
        for (var i = 0; i < path.length; i++) {
                xpriv = derivePrivateKey(xpriv, path[i])
        }
        return xpriv
}


// Set derivation path, derive child keys
// Derivation path is manually set to derive first HD address
derivationPath = [0x80000000, 0x80000000]
child_xpriv = deriveChildPrivate(root_xpriv, derivationPath)
child_xpub = child_xpriv.slice(64, 128)
console.log("\nChild Extended Private Key:", child_xpriv.toString('hex'))

// Derive HD Passhrase
hdPassphrase = pbkdf2.pbkdf2Sync(root_xpub, 'address-hashing', 500, 32, 'sha512')
console.log("\nHD Passphrase:", hdPassphrase.toString('hex'))

// Encrypt derivation path
serializedDerivationPath = cbor.encode(new CborIndefiniteLengthArray(derivationPath))
cipher = new chacha20.ChaCha20Poly1305(hdPassphrase)
encryptedDerivationPath = Buffer.from(cipher.seal(Buffer.from('serokellfore'), serializedDerivationPath))
serializedEncryptedPath = cbor.encode(encryptedDerivationPath)

// Construct HD Wallet Address
addrType = 0
addrAttributes = new Map([[1, serializedEncryptedPath]])
addrRoot = [
        addrType,
        [ addrType, child_xpub ],
        addrAttributes
]

cborAddrRoot = cbor.encode(addrRoot)
sha3AddrRoot = sha3_256(cborAddrRoot)
abstractHash = blake.blake2b(Buffer.from(sha3AddrRoot, 'hex'), null, 28)
address = cbor.encode([
        Buffer.from(abstractHash),
        addrAttributes,
        addrType
])

checksum = CRC.crc32(address)
taggedAddr = new cbor.Tagged(24, address)
address = cbor.encode([taggedAddr, checksum])
address = bs58.encode(address)

console.log('\nHD Address:', address, "\n")
