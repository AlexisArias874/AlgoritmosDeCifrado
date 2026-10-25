import { x25519 } from '@noble/curves/ed25519.js'
import {
  bigIntToBytes,
  CifraError,
  fromBase64,
  randomBytes,
  toBase64,
} from './bytes'
import { MODP_2048, MODP_GENERATOR, hexToBigInt, modPow, randomScalar } from './bigmath'
import { hkdfKey } from './kdf'

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
