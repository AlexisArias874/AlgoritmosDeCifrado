import { blake2b, blake2s } from '@noble/hashes/blake2.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { hmac } from '@noble/hashes/hmac.js'
import { ripemd160, sha1 } from '@noble/hashes/legacy.js'
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { keccak_256, sha3_256, sha3_512 } from '@noble/hashes/sha3.js'
import type { CHash } from '@noble/hashes/utils.js'
import { CifraError, utf8ToBytes } from './bytes'

export type HashId =
  | 'SHA-256'
  | 'SHA-512'
  | 'SHA-384'
  | 'SHA-224'
  | 'SHA3-256'
  | 'SHA3-512'
  | 'Keccak-256'
  | 'BLAKE2b-512'
  | 'BLAKE2s-256'
  | 'BLAKE3'
  | 'SHA-1'
  | 'RIPEMD-160'

export type HashAlgorithm = {
  id: HashId
  bits: number
  family: string
  description: string
  level: 'recomendado' | 'aceptable' | 'obsoleto'
}

export const HASH_ALGORITHMS: HashAlgorithm[] = [
  { id: 'SHA-256', bits: 256, family: 'SHA-2', description: 'Estándar universal. Usado en TLS, Bitcoin, firmas y verificación de descargas.', level: 'recomendado' },
  { id: 'SHA-512', bits: 512, family: 'SHA-2', description: 'Más rápido en CPUs de 64 bits y con mayor margen de seguridad.', level: 'recomendado' },
  { id: 'SHA-384', bits: 384, family: 'SHA-2', description: 'Variante truncada de SHA-512, común en certificados y suites TLS de alta seguridad.', level: 'recomendado' },
  { id: 'SHA-224', bits: 224, family: 'SHA-2', description: 'Versión corta de SHA-256 para sistemas con espacio limitado.', level: 'aceptable' },
  { id: 'SHA3-256', bits: 256, family: 'SHA-3', description: 'Construcción esponja (Keccak) estandarizada en 2015. Alternativa independiente a SHA-2.', level: 'recomendado' },
  { id: 'SHA3-512', bits: 512, family: 'SHA-3', description: 'SHA-3 con 512 bits de salida. Resistente a ataques de extensión de longitud.', level: 'recomendado' },
  { id: 'Keccak-256', bits: 256, family: 'SHA-3', description: 'Keccak original, usado por Ethereum antes de la estandarización de SHA-3.', level: 'aceptable' },
  { id: 'BLAKE2b-512', bits: 512, family: 'BLAKE2', description: 'Muy rápido en software, seguro y usado en Argon2, WireGuard y Zcash.', level: 'recomendado' },
  { id: 'BLAKE2s-256', bits: 256, family: 'BLAKE2', description: 'Versión de BLAKE2 optimizada para plataformas de 32 bits.', level: 'recomendado' },
  { id: 'BLAKE3', bits: 256, family: 'BLAKE3', description: 'Hash paralelizable y verificable, ideal para archivos grandes. Muy veloz.', level: 'recomendado' },
  { id: 'SHA-1', bits: 160, family: 'SHA-1', description: 'Roto para colisiones desde 2017 (SHAttered). Solo para compatibilidad histórica.', level: 'obsoleto' },
  { id: 'RIPEMD-160', bits: 160, family: 'RIPEMD', description: 'Usado en Bitcoin para direcciones. No debe usarse como hash criptográfico moderno.', level: 'obsoleto' },
]

const HASH_FUNCTIONS: Record<HashId, CHash> = {
  'SHA-256': sha256,
  'SHA-512': sha512,
  'SHA-384': sha384,
  'SHA-224': sha224,
  'SHA3-256': sha3_256,
  'SHA3-512': sha3_512,
  'Keccak-256': keccak_256,
  'BLAKE2b-512': blake2b,
  'BLAKE2s-256': blake2s,
  BLAKE3: blake3,
  'SHA-1': sha1,
  'RIPEMD-160': ripemd160,
}

export function hashBytes(id: HashId, data: Uint8Array | string): Uint8Array {
  const fn = HASH_FUNCTIONS[id]
  if (!fn) throw new CifraError('Hash no soportado.')
  return fn(typeof data === 'string' ? utf8ToBytes(data) : data)
}

export function hmacBytes(id: HashId, key: string, message: string): Uint8Array {
  const fn = HASH_FUNCTIONS[id]
  if (!fn) throw new CifraError('Hash no soportado para HMAC.')
  return hmac(fn, utf8ToBytes(key), utf8ToBytes(message))
}

export const HMAC_ALGORITHMS: HashId[] = [
  'SHA-256',
  'SHA-512',
  'SHA3-256',
  'BLAKE2b-512',
  'BLAKE3',
  'SHA-1',
]
