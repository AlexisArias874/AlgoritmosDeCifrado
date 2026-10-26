import { generateKeyPairSync } from 'node:crypto'
import { SYMMETRIC_ALGORITHMS, encryptSymmetric, decryptSymmetric } from '../src/lib/symmetric'
import {
  eciesDecrypt,
  eciesEncrypt,
  elgamalDecrypt,
  elgamalEncrypt,
  generateEcKeyPair,
  generateElGamalKeyPair,
  generateRsaKeyPair,
  rsaDecrypt,
  rsaEncrypt,
} from '../src/lib/asymmetric'
import { SIGNATURE_ALGORITHMS, generateSigKey, signMessage, verifyMessage } from '../src/lib/signatures'
import {
  deriveExchangeKey,
  dhDecrypt,
  dhEncrypt,
  generateDhKeyPair,
  generateModpPair,
  generateX25519Pair,
  modpSharedSecret,
  x25519SharedSecret,
} from '../src/lib/dh'
import {
  generateMlKemKeyPair,
  mlKemDecrypt,
  mlKemEncrypt,
} from '../src/lib/mlkem'
import {
  importDhKeyMaterial,
  importEcKeyMaterial,
  importElGamalKeyMaterial,
  importMlKemKeyMaterial,
  importRsaKeyMaterial,
} from '../src/lib/external-keys'
import { CLASSIC_ALGORITHMS, runClassic } from '../src/lib/classic'
import { toBase64, toHex } from '../src/lib/bytes'

const text = 'Hola 🔐 mundo. Acentos: ñáéíóú. ' + 'x'.repeat(200)
const pem = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${toBase64(der)}\n-----END ${label}-----`
let failures = 0
const check = (name: string, fn: () => void | Promise<void>) => {
  try {
    const result = fn()
    if (result instanceof Promise) {
      return result.then(
        () => console.log('OK  ', name),
        (error) => {
          failures++
          console.log('FAIL', name, error)
        },
      )
    }
    console.log('OK  ', name)
  } catch (error) {
    failures++
    console.log('FAIL', name, error)
  }
}

const main = async () => {
  for (const alg of SYMMETRIC_ALGORITHMS) {
    await check(`sim ${alg.id}`, () => {
      const enc = encryptSymmetric({
        alg: alg.id,
        plaintext: text,
        secret: 'contraseña de prueba 123!',
        secretMode: 'password',
        keyBits: alg.id.startsWith('AES-') ? 256 : undefined,
      })
      const dec = decryptSymmetric(enc.payload, 'contraseña de prueba 123!', 'password')
      if (dec.plaintext !== text) throw new Error('roundtrip mismatch')
      let failed = false
      try {
        decryptSymmetric(enc.payload, 'incorrecta', 'password')
      } catch {
        failed = true
      }
      if (!failed) throw new Error('wrong password did not fail')
    })
  }

  await check('AES raw key', () => {
    const key = 'ab'.repeat(32)
    const enc = encryptSymmetric({ alg: 'AES-GCM', plaintext: text, secret: key, secretMode: 'raw', keyBits: 256 })
    const dec = decryptSymmetric(enc.payload, key, 'raw')
    if (dec.plaintext !== text) throw new Error('raw mismatch')
  })

  for (const bits of [2048]) {
    await check(`RSA ${bits}`, async () => {
      const kp = await generateRsaKeyPair(bits)
      const hybrid = await rsaEncrypt(text, kp.publicKey, 'hybrid')
      if ((await rsaDecrypt(hybrid, kp.privateKey)) !== text) throw new Error('hybrid mismatch')
      const short = 'mensaje corto'
      const direct = await rsaEncrypt(short, kp.publicKey, 'direct')
      if ((await rsaDecrypt(direct, kp.privateKey)) !== short) throw new Error('direct mismatch')
    })
  }

  await check('ECIES', () => {
    const kp = generateEcKeyPair()
    const enc = eciesEncrypt(text, kp.publicKey)
    if (eciesDecrypt(enc, kp.secretKey) !== text) throw new Error('mismatch')
  })

  await check('ElGamal', () => {
    const kp = generateElGamalKeyPair()
    const enc = elgamalEncrypt(text, kp.publicKey)
    if (elgamalDecrypt(enc, kp.secretKey) !== text) throw new Error('mismatch')
  })

  await check('DH híbrido MODP', () => {
    const kp = generateDhKeyPair()
    const enc = dhEncrypt(text, kp.publicKey)
    if (dhDecrypt(enc, kp.secretKey) !== text) throw new Error('mismatch')
  })

  await check('ML-KEM-768 híbrido', () => {
    const kp = generateMlKemKeyPair()
    const enc = mlKemEncrypt(text, kp.publicKey)
    if (mlKemDecrypt(enc, kp.secretKey) !== text) throw new Error('mismatch')
  })

  await check('clave externa RSA PKCS#8', async () => {
    const kp = await generateRsaKeyPair(2048)
    const key = await crypto.subtle.importKey(
      'jwk',
      kp.privateKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt'],
    )
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', key))
    const imported = await importRsaKeyMaterial(pem('PRIVATE KEY', der))
    const enc = await rsaEncrypt(text, kp.publicKey, 'hybrid')
    if ((await rsaDecrypt(enc, imported.privateKey)) !== text) throw new Error('mismatch')
  })

  await check('clave externa RSA PKCS#1', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    })
    const imported = await importRsaKeyMaterial(privateKey)
    const enc = await rsaEncrypt(text, imported.publicKey, 'hybrid')
    if ((await rsaDecrypt(enc, imported.privateKey)) !== text) throw new Error('mismatch')
  })

  await check('clave externa ECC raw', async () => {
    const kp = generateEcKeyPair()
    const imported = await importEcKeyMaterial(kp.secretKey)
    const enc = eciesEncrypt(text, imported.publicKey)
    if (eciesDecrypt(enc, imported.secretKey) !== text) throw new Error('mismatch')
  })

  await check('clave externa ECC PKCS#8', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )
    const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
    const imported = await importEcKeyMaterial(pem('PRIVATE KEY', der))
    const enc = eciesEncrypt(text, imported.publicKey)
    if (eciesDecrypt(enc, imported.secretKey) !== text) throw new Error('mismatch')
  })

  await check('clave externa ElGamal hex', () => {
    const kp = generateElGamalKeyPair()
    const imported = importElGamalKeyMaterial(kp.secretKey)
    const enc = elgamalEncrypt(text, imported.publicKey)
    if (elgamalDecrypt(enc, imported.secretKey) !== text) throw new Error('mismatch')
  })

  await check('clave externa DH hex', () => {
    const kp = generateDhKeyPair()
    const imported = importDhKeyMaterial(kp.secretKey)
    const enc = dhEncrypt(text, imported.publicKey)
    if (dhDecrypt(enc, imported.secretKey) !== text) throw new Error('mismatch')
  })

  await check('clave externa ML-KEM base64', () => {
    const kp = generateMlKemKeyPair()
    const imported = importMlKemKeyMaterial(kp.secretKey)
    const enc = mlKemEncrypt(text, imported.publicKey)
    if (mlKemDecrypt(enc, imported.secretKey) !== text) throw new Error('mismatch')
  })

  for (const alg of SIGNATURE_ALGORITHMS) {
    await check(`sig ${alg.id}`, async () => {
      const kp = await generateSigKey(alg.id)
      const sig = await signMessage(text, kp)
      const result = await verifyMessage(text, sig)
      if (!result.valid) throw new Error('invalid signature')
      const bad = await verifyMessage(text + '!', sig)
      if (bad.valid) throw new Error('tampered message verified')
    })
  }

  await check('DH MODP', () => {
    const a = generateModpPair()
    const b = generateModpPair()
    const sa = modpSharedSecret(a.secretKey, b.publicKey)
    const sb = modpSharedSecret(b.secretKey, a.publicKey)
    if (toHex(sa) !== toHex(sb)) throw new Error('shared mismatch')
    if (toHex(deriveExchangeKey(sa, 'modp')) !== toHex(deriveExchangeKey(sb, 'modp'))) {
      throw new Error('derived mismatch')
    }
  })

  await check('DH X25519', () => {
    const a = generateX25519Pair()
    const b = generateX25519Pair()
    const sa = x25519SharedSecret(a.secretKey, b.publicKey)
    const sb = x25519SharedSecret(b.secretKey, a.publicKey)
    if (toHex(sa) !== toHex(sb)) throw new Error('shared mismatch')
  })

  const sample: Record<string, string> = {
    cesar: 'Hola Mundo 123',
    rot13: 'Hola Mundo 123',
    rot47: 'Hola Mundo 123',
    atbash: 'Hola Mundo 123',
    vigenere: 'Hola Mundo 123',
    beaufort: 'Hola Mundo 123',
    autoclave: 'Hola Mundo 123',
    afin: 'Hola Mundo 123',
    railfence: 'Hola Mundo 123',
    columnar: 'Hola Mundo 123',
    playfair: 'Hola Mundo 123',
    hill: 'Hola Mundo 123',
    bacon: 'Hola Mundo 123',
    morse: 'Hola Mundo 123',
    xor: 'Hola Mundo 123',
    vernam: 'Hola Mundo 123',
    base64: 'Hola Mundo 123 🔐',
    base64url: 'Hola Mundo 123 🔐',
    hex: 'Hola Mundo 123 🔐',
    binario: 'Hola Mundo 123 🔐',
    a1z26: 'Hola Mundo 123',
    url: 'Hola Mundo 123 🔐/?&',
  }

  for (const alg of CLASSIC_ALGORITHMS) {
    await check(`classic ${alg.id}`, () => {
      const params: Record<string, string> = {}
      alg.fields.forEach((f) => (params[f.name] = f.defaultValue))
      if (alg.id === 'hill') params.matrixSize = '2'
      const plain = sample[alg.id]
      let key = params.otpKey
      if (alg.id === 'vernam') {
        const bytes = new TextEncoder().encode(plain)
        key = toHex(crypto.getRandomValues(new Uint8Array(bytes.length)))
        params.otpKey = key
      }
      const enc = runClassic(alg.id, false, plain, params)
      const dec = runClassic(alg.id, true, enc, params)
      let normalized = plain
      if (['playfair', 'hill', 'bacon', 'a1z26'].includes(alg.id)) {
        normalized = plain.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I')
      } else if (alg.id === 'morse') {
        normalized = plain.toUpperCase()
      }
      if (alg.id === 'hill' || alg.id === 'playfair') {
        if (!dec.startsWith(normalized.slice(0, Math.min(normalized.length, 4)))) {
          throw new Error(`unexpected decode: ${dec}`)
        }
      } else if (dec !== normalized) {
        throw new Error(`roundtrip mismatch: ${JSON.stringify(dec)}`)
      }
    })
  }

  if (failures) {
    console.log(`\n${failures} fallos`)
    process.exit(1)
  }
  console.log('\nTodo OK')
}

main()
