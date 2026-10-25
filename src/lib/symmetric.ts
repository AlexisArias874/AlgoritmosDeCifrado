import CryptoJS from 'crypto-js'
import { cbc, cfb, ctr, ecb, gcm } from '@noble/ciphers/aes.js'
import { chacha20, chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { salsa20 } from '@noble/ciphers/salsa.js'
import { decrypt as twofishDecrypt, encrypt as twofishEncrypt, makeSession } from 'twofish-ts'
import {
  CifraError,
  bytesToUtf8,
  decodeEnvelope,
  encodeEnvelope,
  fromBase64,
  randomBytes,
  toBase64,
  toHex,
  utf8ToBytes,
} from './bytes'
import { DEFAULT_PBKDF2_ITERATIONS, deriveKey, resolveKey } from './kdf'

export type SymId =
  | 'AES-GCM'
  | 'AES-CBC'
  | 'AES-CTR'
  | 'AES-CFB'
  | 'AES-ECB'
  | 'ChaCha20-Poly1305'
  | 'XChaCha20-Poly1305'
  | 'ChaCha20'
  | 'Salsa20'
  | 'Twofish-CBC'
  | 'Blowfish-CBC'
  | '3DES-CBC'
  | 'DES-CBC'
  | 'RC4'

export type SymAlgorithm = {
  id: SymId
  family: 'AEAD' | 'Bloque' | 'Flujo' | 'Histórico'
  keyLengths: number[]
  ivLength: number
  year: string
  tagline: string
  description: string
  level: 'recomendado' | 'aceptable' | 'obsoleto' | 'inseguro'
  warning?: string
}

export const SYMMETRIC_ALGORITHMS: SymAlgorithm[] = [
  {
    id: 'AES-GCM',
    family: 'AEAD',
    keyLengths: [16, 24, 32],
    ivLength: 12,
    year: '2001',
    tagline: 'AEAD · bloque 128 bits',
    description:
      'AES en modo Galois/Counter. Cifra y autentica en una sola pasada: detecta cualquier alteración del texto cifrado. Es el algoritmo que protege HTTPS, WhatsApp y discos modernos.',
    level: 'recomendado',
  },
  {
    id: 'ChaCha20-Poly1305',
    family: 'AEAD',
    keyLengths: [32],
    ivLength: 12,
    year: '2014',
    tagline: 'AEAD · flujo',
    description:
      'Cifrado de flujo de Google + autenticación Poly1305. Excelente en teléfonos y dispositivos sin aceleración AES por hardware. Es el estándar de TLS 1.3 y WireGuard.',
    level: 'recomendado',
  },
  {
    id: 'XChaCha20-Poly1305',
    family: 'AEAD',
    keyLengths: [32],
    ivLength: 24,
    year: '2016',
    tagline: 'AEAD · nonce 192 bits',
    description:
      'Variante de ChaCha20 con nonce de 24 bytes. Permite generar nonces aleatorios sin miedo a colisiones, ideal para mensajería con muchas claves.',
    level: 'recomendado',
  },
  {
    id: 'AES-CBC',
    family: 'Bloque',
    keyLengths: [16, 24, 32],
    ivLength: 16,
    year: '2001',
    tagline: 'Bloque · requiere IV',
    description:
      'Cada bloque se encadena con el anterior. Requiere un IV aleatorio y relleno PKCS#7. No autentica por sí solo: en producción debe combinarse con HMAC.',
    level: 'aceptable',
    warning: 'CBC sin MAC es vulnerable a manipulación. Para uso real, prefiere AES-GCM.',
  },
  {
    id: 'AES-CTR',
    family: 'Bloque',
    keyLengths: [16, 24, 32],
    ivLength: 16,
    year: '2001',
    tagline: 'Bloque · contador',
    description:
      'Convierte AES en un cifrado de flujo usando un contador. Muy rápido y paralelizable, pero sin autenticación: un bit cambiado cambia el texto descifrado.',
    level: 'aceptable',
    warning: 'Nunca reutilices el mismo nonce con la misma clave. No autentica los datos.',
  },
  {
    id: 'AES-CFB',
    family: 'Bloque',
    keyLengths: [16, 24, 32],
    ivLength: 16,
    year: '2001',
    tagline: 'Bloque · flujo',
    description:
      'Modo de retroalimentación que permite cifrar byte a byte. Práctico en protocolos antiguos; hoy se sustituye por GCM.',
    level: 'aceptable',
    warning: 'No incluye autenticación de integridad.',
  },
  {
    id: 'AES-ECB',
    family: 'Histórico',
    keyLengths: [16, 24, 32],
    ivLength: 0,
    year: '2001',
    tagline: 'Bloque · sin IV',
    description:
      'Cifra cada bloque de forma independiente. Bloques iguales producen resultados iguales, revelando patrones. Se incluye únicamente con fines didácticos.',
    level: 'inseguro',
    warning: 'ECB filtra patrones y no debe usarse para proteger información real.',
  },
  {
    id: 'ChaCha20',
    family: 'Flujo',
    keyLengths: [32],
    ivLength: 12,
    year: '2008',
    tagline: 'Flujo · sin autenticación',
    description:
      'El cifrado de flujo ChaCha20 sin Poly1305. Rápido y elegante, pero sin autenticación; se muestra para comparar con su versión AEAD.',
    level: 'obsoleto',
    warning: 'Sin autenticación. Usa ChaCha20-Poly1305 para datos reales.',
  },
  {
    id: 'Salsa20',
    family: 'Flujo',
    keyLengths: [32],
    ivLength: 8,
    year: '2005',
    tagline: 'Flujo · nonce 64 bits',
    description:
      'Cifrado de flujo que inspiró a ChaCha20. Sigue siendo seguro con nonces únicos, aunque hoy se prefiere ChaCha20 por su difusión y velocidad.',
    level: 'aceptable',
    warning: 'Sin autenticación y con nonce corto: no reutilizar nunca.',
  },
  {
    id: 'Twofish-CBC',
    family: 'Bloque',
    keyLengths: [32],
    ivLength: 16,
    year: '1998',
    tagline: 'Bloque · 128 bits',
    description:
      'Diseñado por Bruce Schneier como sucesor de Blowfish. Muy seguro, flexible y eficiente en software. Finalista del concurso que ganó AES.',
    level: 'aceptable',
    warning: 'Implementación educativa en CBC; no autentica por sí sola.',
  },
  {
    id: 'Blowfish-CBC',
    family: 'Bloque',
    keyLengths: [32],
    ivLength: 8,
    year: '1993',
    tagline: 'Bloque · 64 bits',
    description:
      'Cifrado por bloques con clave de longitud variable. Fue muy popular en gestores de contraseñas. Su bloque de 64 bits lo hace inadecuado para grandes volúmenes.',
    level: 'aceptable',
    warning: 'Bloque de 64 bits: no recomendado para datos nuevos. Sin autenticación.',
  },
  {
    id: '3DES-CBC',
    family: 'Bloque',
    keyLengths: [24],
    ivLength: 8,
    year: '1998',
    tagline: 'Bloque · clave 168 bits',
    description:
      'Aplica DES tres veces para alargar la clave efectiva. Fue común en bancos y sistemas heredados, pero es lento y hoy está en retirada.',
    level: 'obsoleto',
    warning: 'Obsoleto. Migra a AES-GCM. `crypto-js` lo implementa en software.',
  },
  {
    id: 'DES-CBC',
    family: 'Histórico',
    keyLengths: [8],
    ivLength: 8,
    year: '1977',
    tagline: 'Bloque · clave 56 bits',
    description:
      'Primer estándar federal de cifrado. Su clave de 56 bits se rompe por fuerza bruta en horas o minutos con hardware actual. Solo valor histórico.',
    level: 'inseguro',
    warning: 'DES es inseguro. No protejas información real con él.',
  },
  {
    id: 'RC4',
    family: 'Histórico',
    keyLengths: [16],
    ivLength: 0,
    year: '1987',
    tagline: 'Flujo · inseguro',
    description:
      'Cifrado de flujo que dominó la web temprana (WEP, TLS antiguo). Sus sesgos estadísticos permiten recuperar información. Prohibido en protocolos modernos.',
    level: 'inseguro',
    warning: 'RC4 está roto criptográficamente. Se incluye solo para comparar.',
  },
]

export const symById = (id: SymId): SymAlgorithm => {
  const found = SYMMETRIC_ALGORITHMS.find((alg) => alg.id === id)
  if (!found) throw new CifraError('Algoritmo simétrico desconocido.')
  return found
}

type Envelope = {
  v: 1
  alg: SymId
  kdf: 'PBKDF2-SHA256' | 'raw'
  keyLen: number
  iter?: number
  salt?: string
  iv?: string
  ct: string
  aad?: boolean
}

export type EncryptOptions = {
  alg: SymId
  plaintext: string
  secret: string
  secretMode: 'password' | 'raw'
  keyBits?: number
  iterations?: number
}

export type SymResult = {
  payload: string
  algorithm: SymAlgorithm
  bytes: number
  keyBytes: number
  derived: boolean
}

function headerAad(env: Pick<Envelope, 'alg' | 'kdf' | 'keyLen' | 'iter' | 'salt' | 'iv'>): Uint8Array {
  return utf8ToBytes(
    JSON.stringify({
      v: 1,
      alg: env.alg,
      kdf: env.kdf,
      keyLen: env.keyLen,
      iter: env.iter ?? null,
      salt: env.salt ?? null,
      iv: env.iv ?? null,
    }),
  )
}

function wordArrayToBytes(wordArray: CryptoJS.lib.WordArray): Uint8Array {
  const out = new Uint8Array(wordArray.sigBytes)
  for (let i = 0; i < wordArray.sigBytes; i++) {
    out[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
  }
  return out
}

function legacyBlock(
  kind: 'DES' | '3DES' | 'Blowfish',
  encrypting: boolean,
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  const cipher =
    kind === 'DES' ? CryptoJS.DES : kind === '3DES' ? CryptoJS.TripleDES : CryptoJS.Blowfish
  const keyWa = CryptoJS.enc.Hex.parse(toHex(key))
  const config = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
    iv: CryptoJS.enc.Hex.parse(toHex(iv)),
  }
  if (encrypting) {
    const result = cipher.encrypt(CryptoJS.enc.Hex.parse(toHex(data)), keyWa, config)
    return wordArrayToBytes(result.ciphertext)
  }
  const input = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Hex.parse(toHex(data)),
  })
  const result = cipher.decrypt(input, keyWa, config)
  return wordArrayToBytes(result)
}

function rc4(encrypting: boolean, data: Uint8Array, key: Uint8Array): Uint8Array {
  const keyWa = CryptoJS.enc.Hex.parse(toHex(key))
  if (encrypting) {
    return wordArrayToBytes(
      CryptoJS.RC4.encrypt(CryptoJS.enc.Hex.parse(toHex(data)), keyWa).ciphertext,
    )
  }
  return wordArrayToBytes(
    CryptoJS.RC4.decrypt(
      CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.enc.Hex.parse(toHex(data)),
      }),
      keyWa,
    ),
  )
}

function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const pad = blockSize - (data.length % blockSize)
  const out = new Uint8Array(data.length + pad)
  out.set(data)
  out.fill(pad, data.length)
  return out
}

function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new CifraError('El criptograma no tiene un tamaño de bloque válido.')
  }
  const pad = data[data.length - 1]
  if (pad < 1 || pad > blockSize || pad > data.length) {
    throw new CifraError('Clave incorrecta o relleno PKCS#7 inválido.')
  }
  for (let i = data.length - pad; i < data.length; i++) {
    if (data[i] !== pad) throw new CifraError('Clave incorrecta o datos alterados.')
  }
  return data.subarray(0, data.length - pad)
}

function twofishCbc(encrypting: boolean, data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const session = makeSession(key)
  const block = 16
  if (encrypting) {
    const padded = pkcs7Pad(data, block)
    const out = new Uint8Array(padded.length)
    let previous = iv
    for (let offset = 0; offset < padded.length; offset += block) {
      const input = new Uint8Array(block)
      for (let i = 0; i < block; i++) input[i] = padded[offset + i] ^ previous[i]
      const cipherBlock = new Uint8Array(block)
      twofishEncrypt(input, 0, cipherBlock, 0, session)
      out.set(cipherBlock, offset)
      previous = cipherBlock
    }
    return out
  }
  if (data.length === 0 || data.length % block !== 0) {
    throw new CifraError('Criptograma Twofish inválido.')
  }
  const out = new Uint8Array(data.length)
  let previous = iv
  for (let offset = 0; offset < data.length; offset += block) {
    const cipherBlock = data.subarray(offset, offset + block)
    const plainBlock = new Uint8Array(block)
    twofishDecrypt(cipherBlock, 0, plainBlock, 0, session)
    for (let i = 0; i < block; i++) plainBlock[i] ^= previous[i]
    out.set(plainBlock, offset)
    previous = cipherBlock
  }
  return pkcs7Unpad(out, block)
}

function runCipher(
  alg: SymId,
  encrypting: boolean,
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  switch (alg) {
    case 'AES-GCM':
      return gcm(key, iv, aad)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'AES-CBC':
      return cbc(key, iv)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'AES-CTR':
      return ctr(key, iv)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'AES-CFB':
      return cfb(key, iv)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'AES-ECB':
      return ecb(key)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'ChaCha20-Poly1305':
      return chacha20poly1305(key, iv, aad)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'XChaCha20-Poly1305':
      return xchacha20poly1305(key, iv, aad)[encrypting ? 'encrypt' : 'decrypt'](data)
    case 'ChaCha20':
      return chacha20(key, iv, data)
    case 'Salsa20':
      return salsa20(key, iv, data)
    case 'Twofish-CBC':
      return twofishCbc(encrypting, data, key, iv)
    case 'Blowfish-CBC':
      return legacyBlock('Blowfish', encrypting, data, key, iv)
    case '3DES-CBC':
      return legacyBlock('3DES', encrypting, data, key, iv)
    case 'DES-CBC':
      return legacyBlock('DES', encrypting, data, key, iv)
    case 'RC4':
      return rc4(encrypting, data, key)
    default:
      throw new CifraError('Algoritmo no soportado.')
  }
}

export function encryptSymmetric(options: EncryptOptions): SymResult {
  if (!options.plaintext) throw new CifraError('Escribe el texto que quieres cifrar.')
  const algorithm = symById(options.alg)
  const keyLen =
    algorithm.id.startsWith('AES-') && options.keyBits
      ? Math.floor(options.keyBits / 8)
      : algorithm.keyLengths[0]

  if (!algorithm.keyLengths.includes(keyLen)) {
    throw new CifraError(`Tamaño de clave no válido para ${algorithm.id}.`)
  }

  const derived = options.secretMode === 'password'
  const salt = derived ? randomBytes(16) : undefined
  const iterations = derived ? options.iterations ?? DEFAULT_PBKDF2_ITERATIONS : undefined
  const key = resolveKey(
    options.secretMode,
    options.secret,
    keyLen,
    salt,
    iterations,
  )
  const iv = algorithm.ivLength > 0 ? randomBytes(algorithm.ivLength) : new Uint8Array()

  const env: Envelope = {
    v: 1,
    alg: options.alg,
    kdf: derived ? 'PBKDF2-SHA256' : 'raw',
    keyLen,
    ct: '',
  }
  if (derived) {
    env.salt = toBase64(salt!)
    env.iter = iterations
  }
  if (iv.length > 0) env.iv = toBase64(iv)

  const aad = headerAad(env)
  const ciphertext = runCipher(
    options.alg,
    true,
    utf8ToBytes(options.plaintext),
    key,
    iv,
    aad,
  )

  env.ct = toBase64(ciphertext)
  if (algorithm.family === 'AEAD') env.aad = true

  const payload = encodeEnvelope(env)
  return {
    payload,
    algorithm,
    bytes: ciphertext.length,
    keyBytes: keyLen,
    derived,
  }
}

export function decryptSymmetric(payload: string, secret: string, secretMode: 'password' | 'raw'): {
  plaintext: string
  algorithm: SymAlgorithm
  bytes: number
  keyBytes: number
} {
  const raw = decodeEnvelope(payload)
  if (raw.v !== 1 || typeof raw.alg !== 'string' || typeof raw.ct !== 'string') {
    throw new CifraError('El paquete no tiene el formato CIFRA1 esperado.')
  }
  const algorithm = symById(raw.alg as SymId)
  if (!algorithm.keyLengths.includes(Number(raw.keyLen))) {
    throw new CifraError('El tamaño de clave del paquete no es válido para este algoritmo.')
  }
  const env: Envelope = {
    v: 1,
    alg: raw.alg as SymId,
    kdf: raw.kdf === 'raw' ? 'raw' : 'PBKDF2-SHA256',
    keyLen: Number(raw.keyLen),
    iter: typeof raw.iter === 'number' ? raw.iter : undefined,
    salt: typeof raw.salt === 'string' ? raw.salt : undefined,
    iv: typeof raw.iv === 'string' ? raw.iv : undefined,
    ct: raw.ct,
    aad: raw.aad === true,
  }

  if (secretMode === 'password' && env.kdf !== 'PBKDF2-SHA256') {
    throw new CifraError('Este paquete fue cifrado con una clave cruda. Cambia a "Clave hexadecimal".')
  }
  if (secretMode === 'raw' && env.kdf === 'PBKDF2-SHA256') {
    throw new CifraError('Este paquete usa contraseña. Cambia a "Contraseña".')
  }

  const salt = env.salt ? fromBase64(env.salt) : undefined
  const key = resolveKey(secretMode, secret, env.keyLen, salt, env.iter)
  const iv = env.iv ? fromBase64(env.iv) : new Uint8Array()
  const ciphertext = fromBase64(env.ct)
  const aad = headerAad(env)

  let plaintextBytes: Uint8Array
  try {
    plaintextBytes = runCipher(env.alg, false, ciphertext, key, iv, aad)
  } catch (error) {
    if (error instanceof CifraError) throw error
    throw new CifraError('No se pudo descifrar: clave incorrecta o datos alterados.')
  }

  return {
    plaintext: bytesToUtf8(plaintextBytes),
    algorithm,
    bytes: ciphertext.length,
    keyBytes: env.keyLen,
  }
}

export function randomKeyHex(bytes: number): string {
  return toHex(randomBytes(bytes))
}

export function passwordStrength(password: string): number {
  if (!password) return 0
  let score = 0
  if (password.length >= 8) score++
  if (password.length >= 12) score++
  if (password.length >= 18) score++
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++
  if (/\d/.test(password)) score++
  if (/[^a-zA-Z0-9]/.test(password)) score++
  if (new Set(password).size > Math.min(12, password.length * 0.6)) score++
  return Math.min(4, Math.ceil((score / 7) * 4))
}

export function describeSecret(secret: string, mode: 'password' | 'raw'): string {
  if (!secret) return 'Sin secreto'
  if (mode === 'raw') return `${secret.replace(/\s/g, '').length / 2} bytes de clave`
  return `${secret.length} caracteres`
}

export { deriveKey }
