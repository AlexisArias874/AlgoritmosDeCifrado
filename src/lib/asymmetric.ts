import { gcm } from '@noble/ciphers/aes.js'
import { p256 } from '@noble/curves/nist.js'
import {
  CifraError,
  bigIntToBytes,
  bytesToUtf8,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64,
  randomBytes,
  toBase64,
  toBuffer,
  toHex,
  utf8ToBytes,
} from './bytes'
import { fingerprintFull, hkdfKey } from './kdf'
import { MODP_2048, MODP_GENERATOR, bigIntToHex, modInverse, modPow, randomScalar } from './bigmath'

/* ------------------------------------------------------------------ */
/* RSA-OAEP (WebCrypto)                                                */
/* ------------------------------------------------------------------ */

export type RsaKeyBundle = {
  alg: 'RSA-OAEP'
  bits: number
  publicKey: JsonWebKey
  privateKey: JsonWebKey
  createdAt: number
}

export async function generateRsaKeyPair(bits = 2048): Promise<RsaKeyBundle> {
  if (bits !== 2048 && bits !== 3072 && bits !== 4096) {
    throw new CifraError('RSA debe usar 2048, 3072 o 4096 bits.')
  }
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  )
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const privateKey = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return { alg: 'RSA-OAEP', bits, publicKey, privateKey, createdAt: Date.now() }
}

async function rsaPublic(key: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  )
}

async function rsaPrivate(key: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  )
}

export async function rsaEncrypt(
  plaintext: string,
  publicKey: JsonWebKey,
  mode: 'hybrid' | 'direct',
): Promise<string> {
  if (!plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const key = await rsaPublic(publicKey)
  const plainBytes = utf8ToBytes(plaintext)

  if (mode === 'direct') {
    const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, toBuffer(plainBytes))
    return encodeEnvelope({
      v: 1,
      alg: 'RSA-OAEP-256',
      kdf: 'none',
      ct: toBase64(new Uint8Array(ct)),
    })
  }

  const aesKey = randomBytes(32)
  const iv = randomBytes(12)
  const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, toBuffer(aesKey))
  const ciphertext = gcm(aesKey, iv).encrypt(plainBytes)
  return encodeEnvelope({
    v: 1,
    alg: 'RSA-OAEP-256+A256GCM',
    kdf: 'none',
    k: toBase64(new Uint8Array(wrapped)),
    iv: toBase64(iv),
    ct: toBase64(ciphertext),
  })
}

export async function rsaDecrypt(payload: string, privateKey: JsonWebKey): Promise<string> {
  const env = decodeEnvelope(payload)
  if (env.alg === 'RSA-OAEP-256') {
    const key = await rsaPrivate(privateKey)
    const ct = fromBase64(String(env.ct ?? ''))
    try {
      const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, toBuffer(ct))
      return bytesToUtf8(new Uint8Array(plain))
    } catch {
      throw new CifraError('No se pudo descifrar con RSA. ¿Clave privada incorrecta?')
    }
  }
  if (env.alg !== 'RSA-OAEP-256+A256GCM') {
    throw new CifraError('El paquete no es RSA-OAEP. Revisa el algoritmo seleccionado.')
  }
  const key = await rsaPrivate(privateKey)
  let aesKey: Uint8Array
  try {
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, toBuffer(fromBase64(String(env.k))))
    aesKey = new Uint8Array(raw)
  } catch {
    throw new CifraError('No se pudo desenvolver la clave AES: la clave privada no corresponde.')
  }
  if (aesKey.length !== 32) throw new CifraError('La clave envuelta no es válida.')
  try {
    return bytesToUtf8(
      gcm(aesKey, fromBase64(String(env.iv))).decrypt(fromBase64(String(env.ct))),
    )
  } catch {
    throw new CifraError('No se pudo descifrar: datos alterados o clave privada incorrecta.')
  }
}

export function rsaFingerprint(bundle: RsaKeyBundle): string {
  return fingerprintFull(bundle.publicKey.n ?? '').slice(0, 32).toUpperCase()
}

/* ------------------------------------------------------------------ */
/* ECIES (ECDH P-256 + HKDF-SHA256 + AES-256-GCM)                      */
/* ------------------------------------------------------------------ */

export type EcKeyBundle = {
  alg: 'ECIES-P256'
  secretKey: string
  publicKey: string
  createdAt: number
}

export function generateEcKeyPair(): EcKeyBundle {
  const { secretKey, publicKey } = p256.keygen()
  return {
    alg: 'ECIES-P256',
    secretKey: toBase64(secretKey),
    publicKey: toBase64(publicKey),
    createdAt: Date.now(),
  }
}

const EC_INFO = 'cifra-ecies-p256-v1'

function ecPublicKey(value: string): Uint8Array {
  const key = fromBase64(value.trim())
  if (key.length !== 33) throw new CifraError('La clave pública ECC debe tener 33 bytes comprimidos.')
  return key
}

export function eciesEncrypt(plaintext: string, publicKeyB64: string): string {
  if (!plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const recipient = ecPublicKey(publicKeyB64)
  const ephemeral = p256.keygen()
  const shared = p256.getSharedSecret(ephemeral.secretKey, recipient)
  const salt = randomBytes(16)
  const key = hkdfKey(shared.subarray(1), EC_INFO, 32, salt)
  const iv = randomBytes(12)
  const ct = gcm(key, iv).encrypt(utf8ToBytes(plaintext))
  return encodeEnvelope({
    v: 1,
    alg: 'ECIES-P256-AESGCM',
    kdf: 'HKDF-SHA256',
    epk: toBase64(ephemeral.publicKey),
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(ct),
  })
}

export function eciesDecrypt(payload: string, secretKeyB64: string): string {
  const env = decodeEnvelope(payload)
  if (env.alg !== 'ECIES-P256-AESGCM') {
    throw new CifraError('El paquete no es ECIES P-256. Revisa el algoritmo seleccionado.')
  }
  const secret = fromBase64(secretKeyB64.trim())
  if (secret.length !== 32) throw new CifraError('La clave privada ECC debe tener 32 bytes.')
  const epk = ecPublicKey(String(env.epk ?? ''))
  let shared: Uint8Array
  try {
    shared = p256.getSharedSecret(secret, epk)
  } catch {
    throw new CifraError('La clave pública efímera del paquete no es válida.')
  }
  const salt = fromBase64(String(env.salt ?? ''))
  const key = hkdfKey(shared.subarray(1), EC_INFO, 32, salt)
  try {
    return bytesToUtf8(
      gcm(key, fromBase64(String(env.iv))).decrypt(fromBase64(String(env.ct))),
    )
  } catch {
    throw new CifraError('No se pudo descifrar: clave privada incorrecta o datos alterados.')
  }
}

export function ecFingerprint(bundle: EcKeyBundle): string {
  return toHex(fromBase64(bundle.publicKey)).slice(0, 32).toUpperCase()
}

/* ------------------------------------------------------------------ */
/* ElGamal híbrido sobre el grupo MODP de 2048 bits (RFC 3526)         */
/* ------------------------------------------------------------------ */


export type ElGamalKeyBundle = {
  alg: 'ELGAMAL-2048'
  secretKey: string
  publicKey: string
  group: string
  createdAt: number
}


export function generateElGamalKeyPair(): ElGamalKeyBundle {
  const secret = randomScalar()
  const publicKey = modPow(MODP_GENERATOR, secret, MODP_2048)
  return {
    alg: 'ELGAMAL-2048',
    secretKey: bigIntToHex(secret, 32),
    publicKey: bigIntToHex(publicKey),
    group: 'MODP-2048 (RFC 3526) · g = 2',
    createdAt: Date.now(),
  }
}

export function elgamalEncrypt(plaintext: string, publicKeyHex: string): string {
  if (!plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const y = BigInt('0x' + publicKeyHex.replace(/\s/g, ''))
  if (y <= 1n || y >= MODP_2048 - 1n) throw new CifraError('La clave pública ElGamal no es válida.')

  const aesKey = randomBytes(32)
  const message = BigInt('0x01' + toHex(aesKey))
  const k = randomScalar()
  const c1 = modPow(MODP_GENERATOR, k, MODP_2048)
  const shared = modPow(y, k, MODP_2048)
  const c2 = (message * shared) % MODP_2048
  const iv = randomBytes(12)
  const ct = gcm(aesKey, iv).encrypt(utf8ToBytes(plaintext))

  return encodeEnvelope({
    v: 1,
    alg: 'ELGAMAL-2048-HYBRID',
    kdf: 'none',
    c1: c1.toString(16),
    c2: c2.toString(16),
    iv: toBase64(iv),
    ct: toBase64(ct),
  })
}

export function elgamalDecrypt(payload: string, secretKeyHex: string): string {
  const env = decodeEnvelope(payload)
  if (env.alg !== 'ELGAMAL-2048-HYBRID') {
    throw new CifraError('El paquete no es ElGamal. Revisa el algoritmo seleccionado.')
  }
  let x: bigint
  try {
    x = BigInt('0x' + secretKeyHex.replace(/\s/g, ''))
  } catch {
    throw new CifraError('La clave privada ElGamal no es hexadecimal válida.')
  }
  if (x <= 0n) throw new CifraError('La clave privada ElGamal no es válida.')
  const c1 = BigInt('0x' + String(env.c1 ?? ''))
  const c2 = BigInt('0x' + String(env.c2 ?? ''))
  if (c1 <= 1n || c1 >= MODP_2048 || c2 <= 0n || c2 >= MODP_2048) {
    throw new CifraError('Los valores ElGamal del paquete están fuera de rango.')
  }
  let message: bigint
  try {
    const shared = modPow(c1, x, MODP_2048)
    message = (c2 * modInverse(shared, MODP_2048)) % MODP_2048
  } catch {
    throw new CifraError('Clave privada incorrecta o paquete corrupto.')
  }
  let bytes = bigIntToBytes(message)
  if (bytes.length === 32) bytes = Uint8Array.from([1, ...bytes])
  if (bytes.length !== 33 || bytes[0] !== 1) {
    throw new CifraError('Clave privada incorrecta o paquete corrupto.')
  }
  const aesKey = bytes.subarray(1)
  try {
    return bytesToUtf8(gcm(aesKey, fromBase64(String(env.iv))).decrypt(fromBase64(String(env.ct))))
  } catch {
    throw new CifraError('No se pudo descifrar: clave privada incorrecta o datos alterados.')
  }
}

export function elgamalFingerprint(bundle: ElGamalKeyBundle): string {
  return fingerprintFull(bundle.publicKey).slice(0, 32).toUpperCase()
}

/* ------------------------------------------------------------------ */
/* utilidades de importación / exportación                              */
/* ------------------------------------------------------------------ */

export function publicBundle<T extends object>(bundle: T): Partial<T> {
  const copy = { ...bundle } as Record<string, unknown>
  delete copy.secretKey
  delete copy.privateKey
  return copy as Partial<T>
}

export function safeJsonParse<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T
  } catch {
    throw new CifraError(`El JSON de ${label} no es válido.`)
  }
}
