import { gcm } from '@noble/ciphers/aes.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import {
  bytesToUtf8,
  CifraError,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64,
  randomBytes,
  toBase64,
  toHex,
  utf8ToBytes,
} from './bytes'
import { hkdfKey } from './kdf'

export type MlKemKeyBundle = {
  alg: 'ML-KEM-768'
  publicKey: string
  secretKey: string
  createdAt: number
}

const ML_KEM_INFO = 'cifra-ml-kem-768-aesgcm-v1'

export function generateMlKemKeyPair(): MlKemKeyBundle {
  const { publicKey, secretKey } = ml_kem768.keygen()
  return {
    alg: 'ML-KEM-768',
    publicKey: toBase64(publicKey),
    secretKey: toBase64(secretKey),
    createdAt: Date.now(),
  }
}

export function mlKemFingerprint(bundle: MlKemKeyBundle): string {
  return toHex(fromBase64(bundle.publicKey)).slice(0, 32).toUpperCase()
}

export function mlKemEncrypt(plaintext: string, publicKeyB64: string): string {
  if (!plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const publicKey = fromBase64(publicKeyB64)
  if (publicKey.length !== 1184) {
    throw new CifraError('La clave pública ML-KEM-768 debe tener 1184 bytes.')
  }

  let encapsulated: { cipherText: Uint8Array; sharedSecret: Uint8Array }
  try {
    encapsulated = ml_kem768.encapsulate(publicKey)
  } catch {
    throw new CifraError('La clave pública ML-KEM no es válida.')
  }

  const salt = randomBytes(16)
  const key = hkdfKey(encapsulated.sharedSecret, ML_KEM_INFO, 32, salt)
  const iv = randomBytes(12)
  const ct = gcm(key, iv).encrypt(utf8ToBytes(plaintext))

  return encodeEnvelope({
    v: 1,
    alg: 'ML-KEM-768-A256GCM',
    kdf: 'HKDF-SHA256',
    kem: toBase64(encapsulated.cipherText),
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(ct),
  })
}

export function mlKemDecrypt(payload: string, secretKeyB64: string): string {
  const env = decodeEnvelope(payload)
  if (env.alg !== 'ML-KEM-768-A256GCM') {
    throw new CifraError('El paquete no es ML-KEM-768. Revisa el algoritmo seleccionado.')
  }

  const secretKey = fromBase64(secretKeyB64)
  if (secretKey.length !== 2400) {
    throw new CifraError('La clave privada ML-KEM-768 debe tener 2400 bytes.')
  }

  let sharedSecret: Uint8Array
  try {
    sharedSecret = ml_kem768.decapsulate(fromBase64(String(env.kem ?? '')), secretKey)
  } catch {
    throw new CifraError('La clave privada ML-KEM no corresponde o el paquete está corrupto.')
  }

  const salt = fromBase64(String(env.salt ?? ''))
  const key = hkdfKey(sharedSecret, ML_KEM_INFO, 32, salt)
  try {
    return bytesToUtf8(
      gcm(key, fromBase64(String(env.iv))).decrypt(fromBase64(String(env.ct))),
    )
  } catch {
    throw new CifraError('No se pudo descifrar: clave privada incorrecta o datos alterados.')
  }
}
