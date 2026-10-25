import { CifraError, bytesToBigInt, randomBytes } from './bytes'

/** Grupo MODP de 2048 bits del RFC 3526, generador 2. */
export const MODP_2048 = BigInt(
  '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
)

export const MODP_GENERATOR = 2n
export const MODP_BITS = 2048

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) throw new CifraError('Módulo inválido.')
  let result = 1n
  let b = base % modulus
  if (b < 0n) b += modulus
  let e = exponent
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus
    b = (b * b) % modulus
    e >>= 1n
  }
  return result
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  let oldR = value % modulus
  let r = modulus
  let oldS = 1n
  let s = 0n
  if (oldR < 0n) oldR += modulus
  while (r !== 0n) {
    const q = oldR / r
    ;[oldR, r] = [r, oldR - q * r]
    ;[oldS, s] = [s, oldS - q * s]
  }
  if (oldR !== 1n) throw new CifraError('No existe inverso modular para este valor.')
  return ((oldS % modulus) + modulus) % modulus
}

export function randomScalar(modulus = MODP_2048 - 3n): bigint {
  const bytes = randomBytes(32)
  bytes[0] |= 0x80
  return bytesToBigInt(bytes) % modulus
}

export function hexToBigInt(value: string): bigint {
  const clean = value.replace(/\s/g, '').toLowerCase()
  if (!clean || !/^[0-9a-f]+$/.test(clean)) throw new CifraError('Valor hexadecimal no válido.')
  return BigInt('0x' + clean)
}

export function bigIntToHex(value: bigint, padToBytes?: number): string {
  const hex = value.toString(16)
  return padToBytes ? hex.padStart(padToBytes * 2, '0') : hex
}
