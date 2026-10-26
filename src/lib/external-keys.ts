import { p256 } from '@noble/curves/nist.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import {
  CifraError,
  concatBytes,
  fromBase64,
  fromBase64Url,
  fromHex,
  toBase64,
  toBuffer,
} from './bytes'
import { MODP_2048, MODP_GENERATOR, modPow } from './bigmath'
import type { EcKeyBundle, ElGamalKeyBundle, RsaKeyBundle } from './asymmetric'
import type { DhKeyBundle } from './dh'
import type { MlKemKeyBundle } from './mlkem'

/* ------------------------------------------------------------------ */
/* Utilidades de entrada                                               */
/* ------------------------------------------------------------------ */

function jsonObject(input: string): Record<string, unknown> | null {
  const text = input.trim()
  if (!text.startsWith('{')) return null
  try {
    const parsed = JSON.parse(text) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    throw new CifraError('El JSON de la clave no es válido.')
  }
}

type PemKey = { label: string; der: Uint8Array }

function parsePem(input: string): PemKey | null {
  const match = input.match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/)
  if (!match) return null
  const body = match[2].replace(/[^A-Za-z0-9+/=]/g, '')
  return { label: match[1].trim().toUpperCase(), der: fromBase64(body) }
}

function decodeKeyBytes(input: string): Uint8Array {
  const clean = input.trim().replace(/\s+/g, '')
  const hex = clean.replace(/^0x/i, '')
  if (/^[0-9a-f]+$/i.test(hex) && hex.length % 2 === 0) return fromHex(hex)
  try {
    return fromBase64(clean)
  } catch {
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/')
    return fromBase64(normalized + '='.repeat((4 - (normalized.length % 4)) % 4))
  }
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length)
  const bytes: number[] = []
  let value = length
  while (value > 0) {
    bytes.unshift(value & 0xff)
    value >>= 8
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes)
}

function der(tag: number, content: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(tag), derLength(content.length), content)
}

const RSA_ALGORITHM_IDENTIFIER = Uint8Array.from([
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
])

function pkcs1PrivateToPkcs8(pkcs1: Uint8Array): Uint8Array {
  return der(
    0x30,
    concatBytes(
      Uint8Array.of(0x02, 0x01, 0x00),
      RSA_ALGORITHM_IDENTIFIER,
      der(0x04, pkcs1),
    ),
  )
}

function pkcs1PublicToSpki(pkcs1: Uint8Array): Uint8Array {
  return der(
    0x30,
    concatBytes(RSA_ALGORITHM_IDENTIFIER, der(0x03, concatBytes(Uint8Array.of(0), pkcs1))),
  )
}

async function importRsaJwk(der: Uint8Array, format: 'pkcs8' | 'spki'): Promise<JsonWebKey> {
  const usages: KeyUsage[] = format === 'pkcs8' ? ['decrypt'] : ['encrypt']
  try {
    const key = await crypto.subtle.importKey(
      format,
      toBuffer(der),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      usages,
    )
    return await crypto.subtle.exportKey('jwk', key)
  } catch {
    throw new CifraError(
      'La clave RSA no es válida para RSA-OAEP. Usa una clave PKCS#8, SPKI o JWK RSA.',
    )
  }
}

function rsaPublicJwk(jwk: JsonWebKey): JsonWebKey {
  return { kty: 'RSA', n: jwk.n, e: jwk.e }
}

function rsaBits(jwk: JsonWebKey): number {
  if (!jwk.n) return 2048
  return fromBase64Url(jwk.n).length * 8
}

/* ------------------------------------------------------------------ */
/* RSA                                                                 */
/* ------------------------------------------------------------------ */

export async function importRsaKeyMaterial(input: string): Promise<RsaKeyBundle> {
  const data = jsonObject(input)
  if (data) {
    if (data.alg === 'RSA-OAEP' && (data.publicKey || data.privateKey)) {
      const privateKey = data.privateKey as JsonWebKey | undefined
      const publicKey = (data.publicKey as JsonWebKey | undefined) ??
        (privateKey?.d ? rsaPublicJwk(privateKey) : undefined)
      if (!publicKey) throw new CifraError('El JSON no incluye una clave RSA válida.')
      return {
        alg: 'RSA-OAEP',
        bits: Number(data.bits ?? rsaBits(publicKey)),
        publicKey,
        privateKey: privateKey as JsonWebKey,
        createdAt: Number(data.createdAt ?? Date.now()),
      }
    }
    if (data.kty === 'RSA' && data.n && data.e) {
      const jwk = data as JsonWebKey
      if (jwk.d) {
        return {
          alg: 'RSA-OAEP',
          bits: rsaBits(jwk),
          publicKey: rsaPublicJwk(jwk),
          privateKey: jwk,
          createdAt: Date.now(),
        }
      }
      return {
        alg: 'RSA-OAEP',
        bits: rsaBits(jwk),
        publicKey: jwk,
        privateKey: undefined as unknown as JsonWebKey,
        createdAt: Date.now(),
      }
    }
    throw new CifraError('El JSON no corresponde a una clave RSA.')
  }

  const pem = parsePem(input)
  if (!pem) {
    throw new CifraError(
      'Para RSA pega un JSON exportado, un JWK RSA o una clave PEM (PKCS#8/SPKI).',
    )
  }

  if (pem.label === 'RSA PRIVATE KEY') {
    const jwk = await importRsaJwk(pkcs1PrivateToPkcs8(pem.der), 'pkcs8')
    return {
      alg: 'RSA-OAEP',
      bits: rsaBits(jwk),
      publicKey: rsaPublicJwk(jwk),
      privateKey: jwk,
      createdAt: Date.now(),
    }
  }
  if (pem.label === 'RSA PUBLIC KEY') {
    const jwk = await importRsaJwk(pkcs1PublicToSpki(pem.der), 'spki')
    return {
      alg: 'RSA-OAEP',
      bits: rsaBits(jwk),
      publicKey: jwk,
      privateKey: undefined as unknown as JsonWebKey,
      createdAt: Date.now(),
    }
  }
  if (pem.label === 'PRIVATE KEY') {
    const jwk = await importRsaJwk(pem.der, 'pkcs8')
    return {
      alg: 'RSA-OAEP',
      bits: rsaBits(jwk),
      publicKey: rsaPublicJwk(jwk),
      privateKey: jwk,
      createdAt: Date.now(),
    }
  }
  if (pem.label === 'PUBLIC KEY') {
    const jwk = await importRsaJwk(pem.der, 'spki')
    return {
      alg: 'RSA-OAEP',
      bits: rsaBits(jwk),
      publicKey: jwk,
      privateKey: undefined as unknown as JsonWebKey,
      createdAt: Date.now(),
    }
  }

  throw new CifraError('El PEM no contiene una clave RSA compatible.')
}

/* ------------------------------------------------------------------ */
/* ECC P-256 (ECIES)                                                   */
/* ------------------------------------------------------------------ */

function compressP256(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 33 && bytes.length !== 65) {
    throw new CifraError('La clave pública ECC debe ser un punto P-256 de 33 o 65 bytes.')
  }
  try {
    return p256.Point.fromBytes(bytes).toBytes(true)
  } catch {
    throw new CifraError('La clave pública ECC no es un punto válido de la curva P-256.')
  }
}

function ecFromSecret(secret: Uint8Array): EcKeyBundle {
  if (secret.length !== 32) throw new CifraError('La clave privada ECC P-256 debe tener 32 bytes.')
  let publicKey: Uint8Array
  try {
    publicKey = p256.getPublicKey(secret, true)
  } catch {
    throw new CifraError('La clave privada ECC no es válida.')
  }
  return {
    alg: 'ECIES-P256',
    secretKey: toBase64(secret),
    publicKey: toBase64(publicKey),
    createdAt: Date.now(),
  }
}

function ecFromPublic(publicKey: Uint8Array): EcKeyBundle {
  return {
    alg: 'ECIES-P256',
    secretKey: '',
    publicKey: toBase64(compressP256(publicKey)),
    createdAt: Date.now(),
  }
}

export async function importEcKeyMaterial(input: string): Promise<EcKeyBundle> {
  const data = jsonObject(input)
  if (data) {
    if (data.alg === 'ECIES-P256') {
      const secretText = typeof data.secretKey === 'string' ? data.secretKey : ''
      const publicText = typeof data.publicKey === 'string' ? data.publicKey : ''
      if (secretText) return ecFromSecret(decodeKeyBytes(secretText))
      if (publicText) return ecFromPublic(decodeKeyBytes(publicText))
      throw new CifraError('El JSON no incluye una clave ECC.')
    }
    if (data.kty === 'EC' && data.crv === 'P-256') {
      if (typeof data.d === 'string') {
        return ecFromSecret(fromBase64Url(data.d))
      }
      if (typeof data.x === 'string' && typeof data.y === 'string') {
        return ecFromPublic(
          concatBytes(Uint8Array.of(0x04), fromBase64Url(data.x), fromBase64Url(data.y)),
        )
      }
    }
    throw new CifraError('El JSON no corresponde a una clave ECC P-256.')
  }

  const pem = parsePem(input)
  if (pem) {
    if (pem.label === 'PRIVATE KEY') {
      try {
        const key = await crypto.subtle.importKey(
          'pkcs8',
          toBuffer(pem.der),
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          ['deriveBits'],
        )
        const jwk = await crypto.subtle.exportKey('jwk', key)
        if (!jwk.d) throw new Error('sin escalar')
        return ecFromSecret(fromBase64Url(jwk.d))
      } catch {
        throw new CifraError('La clave PEM no es una clave privada ECC P-256 válida (PKCS#8).')
      }
    }
    if (pem.label === 'PUBLIC KEY') {
      try {
        const key = await crypto.subtle.importKey(
          'spki',
          toBuffer(pem.der),
          { name: 'ECDH', namedCurve: 'P-256' },
          true,
          [],
        )
        const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key))
        return ecFromPublic(raw)
      } catch {
        throw new CifraError('La clave PEM no es una clave pública ECC P-256 válida (SPKI).')
      }
    }
    throw new CifraError(
      'El PEM ECC debe ser PKCS#8 (PRIVATE KEY) o SPKI (PUBLIC KEY). Convierte las claves SEC1.',
    )
  }

  const bytes = decodeKeyBytes(input)
  if (bytes.length === 32) return ecFromSecret(bytes)
  if (bytes.length === 33 || bytes.length === 65) return ecFromPublic(bytes)
  throw new CifraError(
    'La clave ECC debe ser un escalar de 32 bytes (privada) o un punto P-256 de 33/65 bytes (pública).',
  )
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman y ElGamal (MODP 2048)                                */
/* ------------------------------------------------------------------ */

function modpScalarFromText(value: string): bigint {
  const clean = value.trim().replace(/^0x/i, '').replace(/[\s:]/g, '')
  if (!clean || !/^[0-9a-f]+$/i.test(clean)) {
    throw new CifraError('La clave privada debe estar en hexadecimal.')
  }
  if (clean.length > 64) {
    throw new CifraError(
      'Ese valor parece una clave pública. Para descifrar necesitas la clave privada (hex).',
    )
  }
  const scalar = BigInt('0x' + clean)
  if (scalar <= 0n || scalar >= MODP_2048 - 1n) {
    throw new CifraError('La clave privada está fuera del grupo MODP-2048.')
  }
  return scalar
}

function modpPublicScalar(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().replace(/^0x/i, '').replace(/[\s:]/g, '')
  if (!clean || !/^[0-9a-f]+$/i.test(clean)) {
    throw new CifraError('La clave pública debe estar en hexadecimal.')
  }
  return clean.padStart(512, '0')
}

function modpPublicFromSecret(secret: bigint): string {
  return modPow(MODP_GENERATOR, secret, MODP_2048).toString(16).padStart(512, '0')
}

export function importElGamalKeyMaterial(input: string): ElGamalKeyBundle {
  const data = jsonObject(input)
  if (data) {
    if (data.alg !== undefined && data.alg !== 'ELGAMAL-2048') {
      throw new CifraError('El JSON no corresponde a una clave ElGamal.')
    }
    const secretText = typeof data.secretKey === 'string' ? data.secretKey : ''
    const privateText = typeof data.privateKey === 'string' ? data.privateKey : ''
    const publicText = typeof data.publicKey === 'string' ? data.publicKey : ''
    if (secretText || privateText) {
      const secret = modpScalarFromText(secretText || privateText)
      return {
        alg: 'ELGAMAL-2048',
        secretKey: secret.toString(16).padStart(64, '0'),
        publicKey: modpPublicFromSecret(secret),
        group: String(data.group ?? 'MODP-2048 (RFC 3526) · g = 2'),
        createdAt: Number(data.createdAt ?? Date.now()),
      }
    }
    if (publicText) {
      return {
        alg: 'ELGAMAL-2048',
        secretKey: '',
        publicKey: modpPublicScalar(publicText),
        group: String(data.group ?? 'MODP-2048 (RFC 3526) · g = 2'),
        createdAt: Number(data.createdAt ?? Date.now()),
      }
    }
    throw new CifraError('El JSON no incluye una clave ElGamal.')
  }

  const secret = modpScalarFromText(input)
  return {
    alg: 'ELGAMAL-2048',
    secretKey: secret.toString(16).padStart(64, '0'),
    publicKey: modpPublicFromSecret(secret),
    group: 'MODP-2048 (RFC 3526) · g = 2',
    createdAt: Date.now(),
  }
}

export function importDhKeyMaterial(input: string): DhKeyBundle {
  const data = jsonObject(input)
  if (data) {
    if (data.alg !== undefined && data.alg !== 'DH-MODP2048') {
      throw new CifraError('El JSON no corresponde a una clave Diffie-Hellman.')
    }
    const secretText = typeof data.secretKey === 'string' ? data.secretKey : ''
    const privateText = typeof data.privateKey === 'string' ? data.privateKey : ''
    const publicText = typeof data.publicKey === 'string' ? data.publicKey : ''
    if (secretText || privateText) {
      const secret = modpScalarFromText(secretText || privateText)
      return {
        alg: 'DH-MODP2048',
        secretKey: secret.toString(16).padStart(64, '0'),
        publicKey: modpPublicFromSecret(secret),
        group: String(data.group ?? 'MODP 2048 (RFC 3526)'),
        createdAt: Number(data.createdAt ?? Date.now()),
      }
    }
    if (publicText) {
      return {
        alg: 'DH-MODP2048',
        secretKey: '',
        publicKey: modpPublicScalar(publicText),
        group: String(data.group ?? 'MODP 2048 (RFC 3526)'),
        createdAt: Number(data.createdAt ?? Date.now()),
      }
    }
    throw new CifraError('El JSON no incluye una clave Diffie-Hellman.')
  }

  const secret = modpScalarFromText(input)
  return {
    alg: 'DH-MODP2048',
    secretKey: secret.toString(16).padStart(64, '0'),
    publicKey: modpPublicFromSecret(secret),
    group: 'MODP 2048 (RFC 3526)',
    createdAt: Date.now(),
  }
}

/* ------------------------------------------------------------------ */
/* ML-KEM-768                                                          */
/* ------------------------------------------------------------------ */

export function importMlKemKeyMaterial(input: string): MlKemKeyBundle {
  const data = jsonObject(input)
  if (data) {
    if (data.alg !== undefined && data.alg !== 'ML-KEM-768') {
      throw new CifraError('El JSON no corresponde a una clave ML-KEM-768.')
    }
    const secretText = typeof data.secretKey === 'string' ? data.secretKey : ''
    const privateText = typeof data.privateKey === 'string' ? data.privateKey : ''
    const publicText = typeof data.publicKey === 'string' ? data.publicKey : ''
    if (secretText || privateText) {
      return mlKemFromSecret(decodeKeyBytes(secretText || privateText))
    }
    if (publicText) {
      return mlKemFromPublic(decodeKeyBytes(publicText))
    }
    throw new CifraError('El JSON no incluye una clave ML-KEM.')
  }

  const bytes = decodeKeyBytes(input)
  if (bytes.length === 2400) return mlKemFromSecret(bytes)
  if (bytes.length === 1184) return mlKemFromPublic(bytes)
  throw new CifraError(
    'La clave ML-KEM-768 debe medir 2400 bytes (privada) o 1184 bytes (pública).',
  )
}

function mlKemFromSecret(secret: Uint8Array): MlKemKeyBundle {
  if (secret.length !== 2400) throw new CifraError('La clave privada ML-KEM-768 debe tener 2400 bytes.')
  let publicKey: Uint8Array
  try {
    publicKey = ml_kem768.getPublicKey(secret)
  } catch {
    throw new CifraError('La clave privada ML-KEM-768 no es válida.')
  }
  return {
    alg: 'ML-KEM-768',
    secretKey: toBase64(secret),
    publicKey: toBase64(publicKey),
    createdAt: Date.now(),
  }
}

function mlKemFromPublic(publicKey: Uint8Array): MlKemKeyBundle {
  if (publicKey.length !== 1184) {
    throw new CifraError('La clave pública ML-KEM-768 debe tener 1184 bytes.')
  }
  return {
    alg: 'ML-KEM-768',
    secretKey: '',
    publicKey: toBase64(publicKey),
    createdAt: Date.now(),
  }
}
