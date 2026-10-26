import { gcm } from '@noble/ciphers/aes.js'
import { x25519 } from '@noble/curves/ed25519.js'
import {
  bigIntToBytes,
  bytesToUtf8,
  CifraError,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64,
  randomBytes,
  toBase64,
  utf8ToBytes,
} from './bytes'
import { MODP_2048, MODP_GENERATOR, hexToBigInt, modPow, randomScalar } from './bigmath'
import { fingerprintFull, hkdfKey } from './kdf'

export type ExchangePair = {
  secretKey: string
  publicKey: string
}

export const DH_GROUP = {
  name: 'MODP 2048 (RFC 3526)',
  generator: '2',
  bits: 2048,
}

export const X25519_GROUP = {
  name: 'Curve25519 (X25519)',
  generator: '9',
  bits: 255,
}

export function generateModpPair(): ExchangePair {
  const secret = randomScalar()
  const publicKey = modPow(MODP_GENERATOR, secret, MODP_2048)
  return {
    secretKey: secret.toString(16).padStart(64, '0'),
    publicKey: publicKey.toString(16).padStart(512, '0'),
  }
}

export function modpSharedSecret(secretHex: string, peerPublicHex: string): Uint8Array {
  const secret = hexToBigInt(secretHex)
  const peer = hexToBigInt(peerPublicHex)
  if (peer <= 1n || peer >= MODP_2048 - 1n) {
    throw new CifraError('La clave pública DH está fuera del grupo válido.')
  }
  const shared = modPow(peer, secret, MODP_2048)
  return bigIntToBytes(shared, 256)
}

export type DhKeyBundle = {
  alg: 'DH-MODP2048'
  secretKey: string
  publicKey: string
  group: string
  createdAt: number
}

const DH_INFO = 'cifra-dh-modp2048-aesgcm-v1'

export function generateDhKeyPair(): DhKeyBundle {
  const pair = generateModpPair()
  return {
    alg: 'DH-MODP2048',
    secretKey: pair.secretKey,
    publicKey: pair.publicKey,
    group: DH_GROUP.name,
    createdAt: Date.now(),
  }
}

export function dhFingerprint(bundle: DhKeyBundle): string {
  return fingerprintFull(bundle.publicKey).slice(0, 32).toUpperCase()
}

/**
 * Cifrado híbrido con Diffie-Hellman efímero-estático: el emisor crea un
 * par temporal, acuerda una clave con la clave pública del receptor y cifra
 * el texto con AES-256-GCM. Es el mismo patrón que usa ECIES con curvas.
 */
export function dhEncrypt(plaintext: string, recipientPublicHex: string): string {
  if (!plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const ephemeral = generateModpPair()
  const shared = modpSharedSecret(ephemeral.secretKey, recipientPublicHex)
  const salt = randomBytes(16)
  const key = hkdfKey(shared, DH_INFO, 32, salt)
  const iv = randomBytes(12)
  const ct = gcm(key, iv).encrypt(utf8ToBytes(plaintext))

  return encodeEnvelope({
    v: 1,
    alg: 'DH-MODP2048-A256GCM',
    kdf: 'HKDF-SHA256',
    epk: ephemeral.publicKey,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(ct),
  })
}

export function dhDecrypt(payload: string, secretKeyHex: string): string {
  const env = decodeEnvelope(payload)
  if (env.alg !== 'DH-MODP2048-A256GCM') {
    throw new CifraError('El paquete no es Diffie-Hellman MODP-2048. Revisa el algoritmo seleccionado.')
  }
  const shared = modpSharedSecret(secretKeyHex, String(env.epk ?? ''))
  const salt = fromBase64(String(env.salt ?? ''))
  const key = hkdfKey(shared, DH_INFO, 32, salt)
  try {
    return bytesToUtf8(
      gcm(key, fromBase64(String(env.iv))).decrypt(fromBase64(String(env.ct))),
    )
  } catch {
    throw new CifraError('No se pudo descifrar: clave privada incorrecta o datos alterados.')
  }
}

export function generateX25519Pair(): ExchangePair {
  const { secretKey, publicKey } = x25519.keygen()
  return { secretKey: toBase64(secretKey), publicKey: toBase64(publicKey) }
}

export function x25519SharedSecret(secretB64: string, peerPublicB64: string): Uint8Array {
  const secret = fromBase64(secretB64)
  const peer = fromBase64(peerPublicB64)
  if (secret.length !== 32 || peer.length !== 32) {
    throw new CifraError('Las claves X25519 deben medir 32 bytes.')
  }
  return x25519.getSharedSecret(secret, peer)
}

export function deriveExchangeKey(shared: Uint8Array, protocol: string): Uint8Array {
  return hkdfKey(shared, `cifra-exchange-${protocol}-v1`, 32)
}

export function randomExchangeNonce(): string {
  return toBase64(randomBytes(16))
}

export function hexPreview(value: string, head = 12, tail = 8): string {
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}
