import { ed25519 } from '@noble/curves/ed25519.js'
import { p256, p384 } from '@noble/curves/nist.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import {
  CifraError,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64,
  toBase64,
  toBuffer,
  utf8ToBytes,
} from './bytes'
import { fingerprintFull } from './kdf'
import { dsaFingerprint, dsaSign, dsaVerify, generateDsaKeyPair } from './dsa'

export type SigAlg =
  | 'ECDSA-P256'
  | 'ECDSA-P384'
  | 'Ed25519'
  | 'DSA-2048'
  | 'ML-DSA-65'
  | 'RSA-PSS-2048'
  | 'RSA-PSS-3072'

export type SigBundle = {
  alg: SigAlg
  publicKey: string
  privateKey: string
  createdAt: number
}

export const SIGNATURE_ALGORITHMS: {
  id: SigAlg
  name: string
  family: string
  description: string
  level: 'recomendado' | 'aceptable'
}[] = [
  {
    id: 'Ed25519',
    name: 'Ed25519',
    family: 'Curva de Edwards',
    description:
      'Firmas rápidas, deterministas y compactas (64 bytes). Es el estándar moderno en SSH, Signal y criptomonedas. Resistente a errores de nonce.',
    level: 'recomendado',
  },
  {
    id: 'ECDSA-P256',
    name: 'ECDSA P-256 (familia DSA)',
    family: 'Curva de NIST',
    description:
      'ECDSA es la evolución práctica de DSA: firma con curvas elípticas de 256 bits y la misma seguridad que RSA-3072 con claves diminutas. Usado en TLS y pasaportes.',
    level: 'recomendado',
  },
  {
    id: 'ECDSA-P384',
    name: 'ECDSA P-384',
    family: 'Curva de NIST',
    description:
      'Mayor margen de seguridad que P-256 (nivel ~192 bits). Firmas de 96 bytes. Recomendado para datos de larga vida.',
    level: 'recomendado',
  },
  {
    id: 'DSA-2048',
    name: 'DSA 2048/256',
    family: 'DSA clásico',
    description:
      'Digital Signature Algorithm sobre el grupo MODP de 2048 bits con subgrupo primo de 256 bits (RFC 5114). Firma de 64 bytes.',
    level: 'aceptable',
  },
  {
    id: 'ML-DSA-65',
    name: 'ML-DSA-65',
    family: 'Post-cuántico (Dilithium)',
    description:
      'Firma digital post-cuántica estandarizada por el NIST en FIPS 204. Diseñada para resistir ataques de computación cuántica.',
    level: 'recomendado',
  },
  {
    id: 'RSA-PSS-2048',
    name: 'RSA-PSS 2048',
    family: 'RSA',
    description:
      'Firma RSA con relleno probabilístico PSS, más robusta que PKCS#1 v1.5. Claves grandes y verificación lenta, pero compatible con sistemas clásicos.',
    level: 'aceptable',
  },
  {
    id: 'RSA-PSS-3072',
    name: 'RSA-PSS 3072',
    family: 'RSA',
    description:
      'RSA-PSS con módulo de 3072 bits, equivalente aproximado a AES-128. Útil en infraestructura heredada que exige RSA.',
    level: 'aceptable',
  },
]

const ec = (alg: SigAlg) => (alg === 'ECDSA-P384' ? p384 : p256)

function rsaBits(alg: SigAlg): number {
  return alg === 'RSA-PSS-3072' ? 3072 : 2048
}

export async function generateSigKey(alg: SigAlg): Promise<SigBundle> {
  if (alg === 'Ed25519') {
    const { secretKey, publicKey } = ed25519.keygen()
    return {
      alg,
      publicKey: toBase64(publicKey),
      privateKey: toBase64(secretKey),
      createdAt: Date.now(),
    }
  }
  if (alg === 'ECDSA-P256' || alg === 'ECDSA-P384') {
    const { secretKey, publicKey } = ec(alg).keygen()
    return {
      alg,
      publicKey: toBase64(publicKey),
      privateKey: toBase64(secretKey),
      createdAt: Date.now(),
    }
  }
  if (alg === 'DSA-2048') {
    const pair = generateDsaKeyPair()
    return {
      alg,
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      createdAt: pair.createdAt,
    }
  }
  if (alg === 'ML-DSA-65') {
    const { secretKey, publicKey } = ml_dsa65.keygen()
    return {
      alg,
      publicKey: toBase64(publicKey),
      privateKey: toBase64(secretKey),
      createdAt: Date.now(),
    }
  }

  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: rsaBits(alg),
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
  return {
    alg,
    publicKey: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)),
    privateKey: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)),
    createdAt: Date.now(),
  }
}

export function sigFingerprint(bundle: SigBundle): string {
  if (bundle.alg === 'DSA-2048') return dsaFingerprint(bundle.publicKey)
  return fingerprintFull(bundle.publicKey).slice(0, 32).toUpperCase()
}

export async function signMessage(message: string, bundle: SigBundle): Promise<string> {
  if (!message) throw new CifraError('Escribe el mensaje que quieres firmar.')
  const data = utf8ToBytes(message)
  let signature: Uint8Array

  if (bundle.alg === 'Ed25519') {
    signature = ed25519.sign(data, fromBase64(bundle.privateKey))
  } else if (bundle.alg === 'ECDSA-P256' || bundle.alg === 'ECDSA-P384') {
    signature = ec(bundle.alg).sign(data, fromBase64(bundle.privateKey), { format: 'compact' })
  } else if (bundle.alg === 'DSA-2048') {
    signature = dsaSign(data, bundle.privateKey)
  } else if (bundle.alg === 'ML-DSA-65') {
    signature = ml_dsa65.sign(data, fromBase64(bundle.privateKey))
  } else {
    const key = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(bundle.privateKey) as JsonWebKey,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const raw = await crypto.subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      key,
      toBuffer(data),
    )
    signature = new Uint8Array(raw)
  }

  return encodeEnvelope({
    v: 1,
    alg: bundle.alg,
    sig: toBase64(signature),
    publicKey: bundle.publicKey,
    fingerprint: sigFingerprint(bundle),
  })
}

export async function verifyMessage(
  message: string,
  signaturePackage: string,
): Promise<{ valid: boolean; alg: string; publicKey: string; fingerprint: string }> {
  const env = decodeEnvelope(signaturePackage)
  const alg = String(env.alg ?? '') as SigAlg
  const sig = fromBase64(String(env.sig ?? ''))
  const publicKey = String(env.publicKey ?? '')
  if (!publicKey) throw new CifraError('La firma no incluye la clave pública.')
  if (!SIGNATURE_ALGORITHMS.some((item) => item.id === alg)) {
    throw new CifraError('Algoritmo de firma no soportado en este paquete.')
  }
  const data = utf8ToBytes(message)
  let valid = false

  if (alg === 'Ed25519') {
    valid = ed25519.verify(sig, data, fromBase64(publicKey), { zip215: false })
  } else if (alg === 'ECDSA-P256' || alg === 'ECDSA-P384') {
    valid = ec(alg).verify(sig, data, fromBase64(publicKey))
  } else if (alg === 'DSA-2048') {
    valid = dsaVerify(data, sig, publicKey)
  } else if (alg === 'ML-DSA-65') {
    valid = ml_dsa65.verify(sig, data, fromBase64(publicKey))
  } else {
    const key = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(publicKey) as JsonWebKey,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify'],
    )
    valid = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, key, toBuffer(sig), toBuffer(data))
  }

  return {
    valid,
    alg,
    publicKey,
    fingerprint:
      alg === 'DSA-2048'
        ? dsaFingerprint(publicKey)
        : fingerprintFull(publicKey).slice(0, 32).toUpperCase(),
  }
}
