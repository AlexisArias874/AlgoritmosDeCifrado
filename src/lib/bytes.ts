/** Utilidades de bytes, codificación y manejo de errores. */

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export class CifraError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CifraError'
  }
}

export function utf8ToBytes(text: string): Uint8Array {
  return encoder.encode(text)
}

export function bytesToUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes)
  } catch {
    throw new CifraError(
      'El resultado no es texto UTF-8 válido. ¿Clave incorrecta, datos corruptos o algoritmo equivocado?',
    )
  }
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

/** Devuelve un ArrayBuffer independiente para APIs WebCrypto. */
export function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}

/** Convierte bytes a base64 estándar (funciona con textos largos). */
export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

export function fromBase64(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, '')
  try {
    const binary = atob(clean)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
    return out
  } catch {
    throw new CifraError('El texto no es base64 válido.')
  }
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  return fromBase64(padded)
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(value: string): Uint8Array {
  const clean = value.replace(/[\s:]/g, '').toLowerCase()
  if (clean.length === 0) return new Uint8Array()
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new CifraError('El hexadecimal no es válido (debe tener un número par de caracteres 0-9, a-f).')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Envoltorio legible para transportar datos cifrados. */
const ENVELOPE_PREFIX = 'CIFRA1.'

export function encodeEnvelope(payload: object): string {
  return ENVELOPE_PREFIX + toBase64Url(utf8ToBytes(JSON.stringify(payload)))
}

export function decodeEnvelope(input: string): Record<string, unknown> {
  const trimmed = input.trim()
  if (!trimmed) throw new CifraError('Pega primero un texto cifrado.')

  let raw = trimmed
  if (trimmed.startsWith(ENVELOPE_PREFIX)) {
    raw = bytesToUtf8(fromBase64Url(trimmed.slice(ENVELOPE_PREFIX.length)))
  } else if (trimmed.startsWith('{')) {
    raw = trimmed
  } else {
    // Compatibilidad: base64 de un JSON (con o sin espacios).
    try {
      const candidate = bytesToUtf8(fromBase64(trimmed))
      if (candidate.trim().startsWith('{')) raw = candidate
    } catch {
      throw new CifraError('Formato no reconocido. Se esperaba un paquete CIFRA1, JSON o base64 de JSON.')
    }
  }

  try {
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('objeto')
    return parsed as Record<string, unknown>
  } catch {
    throw new CifraError('El paquete cifrado no contiene un JSON válido.')
  }
}

export function formatError(error: unknown): string {
  if (error instanceof CifraError) return error.message
  if (error instanceof Error) {
    if (/operation failed|decrypt|tag|auth/i.test(error.message)) {
      return 'No se pudo descifrar: la clave es incorrecta o los datos fueron alterados.'
    }
    return error.message
  }
  return 'Ocurrió un error inesperado.'
}

/** Convierte cualquier cadena de bytes a BigInt (big-endian). */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt('0x' + toHex(bytes))
}

export function bigIntToBytes(value: bigint, length?: number): Uint8Array {
  let hex = value.toString(16)
  if (hex.length % 2) hex = '0' + hex
  let bytes = fromHex(hex)
  if (length !== undefined) {
    if (bytes.length > length) throw new CifraError('El número no cabe en el tamaño solicitado.')
    const padded = new Uint8Array(length)
    padded.set(bytes, length - bytes.length)
    bytes = padded
  }
  return bytes
}

export async function copyText(text: string): Promise<void> {
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // Fallback para navegadores sin permiso de portapapeles.
    const area = document.createElement('textarea')
    area.value = text
    area.style.position = 'fixed'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    document.execCommand('copy')
    document.body.removeChild(area)
  }
}

export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
