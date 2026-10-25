import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { scrypt, scryptAsync } from '@noble/hashes/scrypt.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { CifraError, bytesToUtf8, fromHex, toHex, utf8ToBytes } from './bytes'

export const DEFAULT_PBKDF2_ITERATIONS = 210_000

export function deriveKey(
  password: string,
  salt: Uint8Array,
  length: number,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
): Uint8Array {
  if (!password) throw new CifraError('Escribe una contraseña para derivar la clave.')
  if (iterations < 10_000) throw new CifraError('Usa al menos 10.000 iteraciones para PBKDF2.')
  return pbkdf2(sha256, utf8ToBytes(password), salt, { c: iterations, dkLen: length })
}

export type KeyMaterial = {
  key: Uint8Array
  salt?: Uint8Array
  iterations?: number
}

/** Deriva la clave de un paquete o interpreta una clave hexadecimal cruda. */
export function resolveKey(
  mode: 'password' | 'raw',
  secret: string,
  length: number,
  salt: Uint8Array | undefined,
  iterations: number | undefined,
): Uint8Array {
  if (mode === 'raw') {
    const key = fromHex(secret)
    if (key.length !== length) {
      throw new CifraError(`La clave cruda debe tener exactamente ${length} bytes (${length * 2} caracteres hex).`)
    }
    return key
  }
  if (!salt) throw new CifraError('El paquete no incluye la sal necesaria para derivar la clave.')
  return deriveKey(secret, salt, length, iterations ?? DEFAULT_PBKDF2_ITERATIONS)
}

export function hkdfKey(
  input: Uint8Array,
  info: string,
  length = 32,
  salt?: Uint8Array,
): Uint8Array {
  return hkdf(sha256, input, salt, utf8ToBytes(info), length)
}

export function deriveScrypt(
  password: string,
  salt: Uint8Array,
  opts: { N: number; r: number; p: number; dkLen: number },
): Uint8Array {
  return scrypt(utf8ToBytes(password), salt, opts)
}

export async function deriveScryptAsync(
  password: string,
  salt: Uint8Array,
  opts: { N: number; r: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  return scryptAsync(utf8ToBytes(password), salt, opts)
}

export async function derivePbkdf2Async(
  password: string,
  salt: Uint8Array,
  length: number,
  iterations: number,
): Promise<Uint8Array> {
  return pbkdf2Async(sha256, utf8ToBytes(password), salt, { c: iterations, dkLen: length })
}

export async function deriveArgon2id(
  password: string,
  salt: Uint8Array,
  opts: { t: number; m: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  return argon2idAsync(utf8ToBytes(password), salt, opts)
}

export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  return sha256(typeof data === 'string' ? utf8ToBytes(data) : data)
}

export function sha512Bytes(data: string | Uint8Array): Uint8Array {
  return sha512(typeof data === 'string' ? utf8ToBytes(data) : data)
}

/** Huella corta y legible de una clave o mensaje. */
export function fingerprint(data: string | Uint8Array): string {
  const hex = toHex(sha256Bytes(data))
  return (hex.match(/.{1,4}/g) ?? []).slice(0, 8).join(' ')
}

export function fingerprintFull(data: string | Uint8Array): string {
  return toHex(sha256Bytes(data))
}

export function randomSalt(length = 16): Uint8Array {
  const salt = new Uint8Array(length)
  crypto.getRandomValues(salt)
  return salt
}

export function phraseFromBytes(bytes: Uint8Array): string {
  try {
    return bytesToUtf8(bytes)
  } catch {
    return toHex(bytes)
  }
}
