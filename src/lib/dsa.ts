import { sha256 } from '@noble/hashes/sha2.js'
import {
  bigIntToBytes,
  bytesToBigInt,
  CifraError,
  concatBytes,
  fromHex,
  randomBytes,
} from './bytes'
import { modInverse, modPow } from './bigmath'

/**
 * DSA clásico sobre el grupo MODP de 2048 bits con subgrupo primo de 256
 * bits definido en el RFC 5114 (sección 2.3).
 */
export const DSA_P = BigInt(
  '0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2' +
    '5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30' +
    '16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD' +
    '5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B' +
    '6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C' +
    '4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E' +
    'F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9' +
    '67E144E5140564251CCACB83E6B486F6B3CA3F7971506026' +
    'C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3' +
    '75F26375D7014103A4B54330C198AF126116D2276E11715F' +
    '693877FAD7EF09CADB094AE91E1A1597',
)

export const DSA_Q = BigInt(
  '0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3',
)

export const DSA_G = BigInt(
  '0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054' +
    '07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555' +
    'BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18' +
    'A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B' +
    '777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83' +
    '1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55' +
    'A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14' +
    'C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915' +
    'B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6' +
    '184B523D1DB246C32F63078490F00EF8D647D148D4795451' +
    '5E2327CFEF98C582664B4C0F6CC41659',
)

export type DsaKeyBundle = {
  alg: 'DSA-2048'
  publicKey: string
  privateKey: string
  createdAt: number
}

function randomBelow(limit: bigint): bigint {
  const bytes = randomBytes(32)
  bytes[0] &= 0x7f
  return bytesToBigInt(bytes) % limit
}

function hashToInt(message: Uint8Array): bigint {
  return bytesToBigInt(sha256(message)) % DSA_Q
}

export function generateDsaKeyPair(): DsaKeyBundle {
  const x = randomBelow(DSA_Q - 1n) + 1n
  const y = modPow(DSA_G, x, DSA_P)
  return {
    alg: 'DSA-2048',
    publicKey: y.toString(16).padStart(512, '0'),
    privateKey: x.toString(16).padStart(64, '0'),
    createdAt: Date.now(),
  }
}

export function dsaSign(message: Uint8Array, secretKeyHex: string): Uint8Array {
  const x = BigInt('0x' + secretKeyHex.replace(/\s/g, ''))
  if (x <= 0n || x >= DSA_Q) throw new CifraError('La clave privada DSA no es válida.')
  const z = hashToInt(message)

  for (let attempt = 0; attempt < 24; attempt++) {
    const k = randomBelow(DSA_Q - 1n) + 1n
    const r = modPow(DSA_G, k, DSA_P) % DSA_Q
    if (r === 0n) continue
    let s: bigint
    try {
      s = (modInverse(k, DSA_Q) * (z + x * r)) % DSA_Q
    } catch {
      continue
    }
    if (s === 0n) continue
    return concatBytes(bigIntToBytes(r, 32), bigIntToBytes(s, 32))
  }

  throw new CifraError('No se pudo generar la firma DSA. Inténtalo de nuevo.')
}

export function dsaVerify(message: Uint8Array, signature: Uint8Array, publicKeyHex: string): boolean {
  if (signature.length !== 64) return false
  const r = bytesToBigInt(signature.subarray(0, 32))
  const s = bytesToBigInt(signature.subarray(32))
  if (r <= 0n || r >= DSA_Q || s <= 0n || s >= DSA_Q) return false

  let y: bigint
  try {
    y = BigInt('0x' + publicKeyHex.replace(/\s/g, ''))
  } catch {
    return false
  }
  if (y <= 1n || y >= DSA_P) return false

  let w: bigint
  try {
    w = modInverse(s, DSA_Q)
  } catch {
    return false
  }
  const z = hashToInt(message)
  const u1 = (z * w) % DSA_Q
  const u2 = (r * w) % DSA_Q
  const v = ((modPow(DSA_G, u1, DSA_P) * modPow(y, u2, DSA_P)) % DSA_P) % DSA_Q
  return v === r
}

export function dsaFingerprint(publicKeyHex: string): string {
  const clean = publicKeyHex.replace(/\s/g, '')
  const bytes = fromHex(clean.length % 2 ? '0' + clean : clean)
  let out = ''
  for (const byte of sha256(bytes)) out += byte.toString(16).padStart(2, '0')
  return out.slice(0, 32).toUpperCase()
}
