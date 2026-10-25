import {
  CifraError,
  fromBase64,
  fromBase64Url,
  fromHex,
  toBase64,
  toBase64Url,
  toHex,
  utf8ToBytes,
  bytesToUtf8,
  randomBytes,
} from './bytes'

export type ClassicId =
  | 'cesar'
  | 'rot13'
  | 'rot47'
  | 'atbash'
  | 'vigenere'
  | 'beaufort'
  | 'autoclave'
  | 'afin'
  | 'railfence'
  | 'columnar'
  | 'playfair'
  | 'hill'
  | 'bacon'
  | 'morse'
  | 'xor'
  | 'vernam'
  | 'base64'
  | 'base64url'
  | 'hex'
  | 'binario'
  | 'a1z26'
  | 'url'

export type ClassicField = {
  name: string
  label: string
  kind: 'text' | 'number' | 'select'
  placeholder?: string
  defaultValue: string
  help?: string
  options?: { value: string; label: string }[]
  mono?: boolean
}

export type ClassicAlgorithm = {
  id: ClassicId
  name: string
  family: 'Sustitución' | 'Transposición' | 'Poligráfico' | 'Codificación' | 'Flujo'
  description: string
  level: 'educativo' | 'débil' | 'codificación'
  fields: ClassicField[]
}

export const CLASSIC_ALGORITHMS: ClassicAlgorithm[] = [
  {
    id: 'cesar',
    name: 'César',
    family: 'Sustitución',
    description:
      'Desplaza cada letra un número fijo de posiciones. Julio César lo usaba con desplazamiento 3. Solo hay 25 claves posibles: se rompe probándolas todas.',
    level: 'débil',
    fields: [{ name: 'shift', label: 'Desplazamiento', kind: 'number', defaultValue: '3' }],
  },
  {
    id: 'rot13',
    name: 'ROT13',
    family: 'Sustitución',
    description:
      'César con desplazamiento 13. Es su propio inverso, por eso se usaba en foros para ocultar spoilers, no para proteger secretos.',
    level: 'educativo',
    fields: [],
  },
  {
    id: 'rot47',
    name: 'ROT47',
    family: 'Sustitución',
    description:
      'Rota 47 posiciones los 94 caracteres ASCII imprimibles. Afecta también números y signos. No aporta seguridad real.',
    level: 'educativo',
    fields: [],
  },
  {
    id: 'atbash',
    name: 'Atbash',
    family: 'Sustitución',
    description:
      'Invierte el alfabeto: A↔Z, B↔Y. Cifrado hebreo milenario; también es su propio inverso.',
    level: 'educativo',
    fields: [],
  },
  {
    id: 'vigenere',
    name: 'Vigenère',
    family: 'Sustitución',
    description:
      'Usa una palabra clave para desplazar cada letra de forma distinta. Fue considerado indescifrable durante siglos hasta el análisis de Kasiski.',
    level: 'débil',
    fields: [{ name: 'key', label: 'Palabra clave', kind: 'text', defaultValue: 'CIFRA', placeholder: 'CLAVE' }],
  },
  {
    id: 'beaufort',
    name: 'Beaufort',
    family: 'Sustitución',
    description:
      'Variante del Vigenère donde la clave menos la letra produce el cifrado. Es recíproca: el mismo proceso cifra y descifra.',
    level: 'débil',
    fields: [{ name: 'key', label: 'Palabra clave', kind: 'text', defaultValue: 'FORTALEZA', placeholder: 'CLAVE' }],
  },
  {
    id: 'autoclave',
    name: 'Autoclave (autokey)',
    family: 'Sustitución',
    description:
      'La clave se extiende con el propio texto claro para evitar la repetición que delata al Vigenère. Mejora la seguridad, pero sigue siendo clásico.',
    level: 'débil',
    fields: [{ name: 'key', label: 'Clave inicial', kind: 'text', defaultValue: 'LUNA', placeholder: 'CLAVE' }],
  },
  {
    id: 'afin',
    name: 'Afín',
    family: 'Sustitución',
    description:
      'Aplica una función lineal modular: C = (a·P + b) mod 26. La clave "a" debe ser coprima con 26 para poder invertir la operación.',
    level: 'débil',
    fields: [
      { name: 'a', label: 'Multiplicador (a)', kind: 'number', defaultValue: '5', help: 'Coprimo con 26: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25' },
      { name: 'b', label: 'Desplazamiento (b)', kind: 'number', defaultValue: '8' },
    ],
  },
  {
    id: 'railfence',
    name: 'Cerca de rieles',
    family: 'Transposición',
    description:
      'Escribe el mensaje en zigzag sobre varios "rieles" y lo lee por filas. No cambia letras, solo su orden. Cae con análisis de anagramas.',
    level: 'educativo',
    fields: [{ name: 'rails', label: 'Rieles', kind: 'number', defaultValue: '3' }],
  },
  {
    id: 'columnar',
    name: 'Transposición columnar',
    family: 'Transposición',
    description:
      'Coloca el texto por filas y lo extrae por columnas según el orden alfabético de una palabra clave. Fue usada por ejércitos hasta el siglo XX.',
    level: 'educativo',
    fields: [{ name: 'key', label: 'Palabra clave', kind: 'text', defaultValue: 'MURCIELAGO', placeholder: 'CLAVE' }],
  },
  {
    id: 'playfair',
    name: 'Playfair',
    family: 'Poligráfico',
    description:
      'Cifra pares de letras usando una matriz 5×5. Fue el primer cifrado digráfico práctico, adoptado por el ejército británico en la Guerra de los Bóeres.',
    level: 'educativo',
    fields: [{ name: 'key', label: 'Palabra clave', kind: 'text', defaultValue: 'MONARQUIA', placeholder: 'CLAVE' }],
  },
  {
    id: 'hill',
    name: 'Hill',
    family: 'Poligráfico',
    description:
      'Multiplica bloques de letras por una matriz invertible módulo 26. Fue el primer cifrado que usaba álgebra lineal; vulnerable a texto conocido.',
    level: 'educativo',
    fields: [
      {
        name: 'matrixSize',
        label: 'Tamaño de matriz',
        kind: 'select',
        defaultValue: '2',
        options: [
          { value: '2', label: '2 × 2' },
          { value: '3', label: '3 × 3' },
        ],
      },
      {
        name: 'matrix',
        label: 'Matriz (números separados por espacios)',
        kind: 'text',
        defaultValue: '3 3 2 5',
        mono: true,
        help: '2×2: 4 números · 3×3: 9 números. El determinante debe ser coprimo con 26.',
      },
    ],
  },
  {
    id: 'bacon',
    name: 'Bacon',
    family: 'Codificación',
    description:
      'Representa cada letra con 5 símbolos A/B (5 bits). Francis Bacon lo ideó en 1605 como esteganografía: el mensaje se escondía en tipografías distintas.',
    level: 'educativo',
    fields: [],
  },
  {
    id: 'morse',
    name: 'Morse',
    family: 'Codificación',
    description:
      'Codificación de puntos y rayas para telecomunicaciones. No es cifrado: cualquiera que conozca el código puede leerlo al instante.',
    level: 'codificación',
    fields: [],
  },
  {
    id: 'xor',
    name: 'XOR con clave de texto',
    family: 'Flujo',
    description:
      'Combina cada byte con la clave mediante OR exclusivo. Si la clave se repite, el patrón se filtra. Útil para entender los cifrados de flujo.',
    level: 'débil',
    fields: [{ name: 'key', label: 'Clave', kind: 'text', defaultValue: 'cifra', placeholder: 'clave secreta' }],
  },
  {
    id: 'vernam',
    name: 'Vernam / OTP',
    family: 'Flujo',
    description:
      'XOR con una clave aleatoria tan larga como el mensaje. Es el único cifrado teóricamente indescifrable si la clave es verdaderamente aleatoria y de un solo uso.',
    level: 'débil',
    fields: [
      {
        name: 'otpKey',
        label: 'Clave de un solo uso (hex)',
        kind: 'text',
        defaultValue: '',
        mono: true,
        help: 'Debe tener la misma longitud en bytes que el mensaje. Genera una nueva para cada uso.',
      },
    ],
  },
  {
    id: 'base64',
    name: 'Base64',
    family: 'Codificación',
    description:
      'Representa bytes con 64 caracteres imprimibles. No cifra: cualquiera puede decodificarlo. Se usa para transportar datos en correo, JSON y URLs.',
    level: 'codificación',
    fields: [],
  },
  {
    id: 'base64url',
    name: 'Base64URL',
    family: 'Codificación',
    description:
      'Variante de Base64 segura para URLs (usa - y _ en lugar de + y /). Tampoco aporta confidencialidad.',
    level: 'codificación',
    fields: [],
  },
  {
    id: 'hex',
    name: 'Hexadecimal',
    family: 'Codificación',
    description:
      'Cada byte se convierte en dos dígitos hexadecimales. Es una representación legible, no un cifrado.',
    level: 'codificación',
    fields: [],
  },
  {
    id: 'binario',
    name: 'Binario',
    family: 'Codificación',
    description:
      'Cada byte se escribe con 8 bits. Útil para visualizar cómo se almacena la información; cero confidencialidad.',
    level: 'codificación',
    fields: [],
  },
  {
    id: 'a1z26',
    name: 'A1Z26',
    family: 'Codificación',
    description:
      'Sustituye A=1, B=2… Z=26. Es un cifrado de sustitución trivial que además funciona como codificación numérica.',
    level: 'educativo',
    fields: [],
  },
  {
    id: 'url',
    name: 'URL encode',
    family: 'Codificación',
    description:
      'Escapa caracteres especiales para que viajen dentro de una URL. No es cifrado, solo formato de transporte.',
    level: 'codificación',
    fields: [],
  },
]

export const classicById = (id: ClassicId): ClassicAlgorithm => {
  const found = CLASSIC_ALGORITHMS.find((alg) => alg.id === id)
  if (!found) throw new CifraError('Algoritmo clásico desconocido.')
  return found
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

const isLetter = (char: string) => /^[a-zA-Z]$/.test(char)
const isUpper = (char: string) => char === char.toUpperCase()

function shiftLetter(char: string, shift: number): string {
  if (!isLetter(char)) return char
  const base = isUpper(char) ? 65 : 97
  const index = char.charCodeAt(0) - base
  return String.fromCharCode(base + (((index + shift) % 26) + 26) % 26)
}

function letterIndex(char: string): number {
  return char.toUpperCase().charCodeAt(0) - 65
}

function lettersOnly(text: string): string {
  return text.toUpperCase().replace(/[^A-Z]/g, '')
}

function mod(a: number, n: number): number {
  return ((a % n) + n) % n
}

function gcd(a: number, b: number): number {
  while (b) [a, b] = [b, a % b]
  return Math.abs(a)
}

function modInverseNumber(a: number, n: number): number {
  const original = a
  a = mod(a, n)
  for (let x = 1; x < n; x++) {
    if ((a * x) % n === 1) return x
  }
  throw new CifraError(`El valor ${original} no tiene inverso módulo ${n}.`)
}

/* ----------------------------- sustituciones ---------------------------- */

function cesar(text: string, shift: number): string {
  return Array.from(text, (char) => shiftLetter(char, shift)).join('')
}

function rot47(text: string): string {
  return Array.from(text, (char) => {
    const code = char.charCodeAt(0)
    if (code >= 33 && code <= 126) return String.fromCharCode(33 + ((code - 33 + 47) % 94))
    return char
  }).join('')
}

function atbash(text: string): string {
  return Array.from(text, (char) => {
    if (!isLetter(char)) return char
    const base = isUpper(char) ? 65 : 97
    return String.fromCharCode(base + (25 - (char.charCodeAt(0) - base)))
  }).join('')
}

function polyalphabetic(text: string, key: string, mode: 'vigenere' | 'beaufort' | 'autokey', decrypt: boolean): string {
  const cleanKey = lettersOnly(key)
  if (!cleanKey) throw new CifraError('Escribe una palabra clave con letras.')
  let keyStream = cleanKey
  if (mode === 'autokey' && !decrypt) {
    keyStream = cleanKey + lettersOnly(text)
  }
  let keyIndex = 0
  let plainHistory = ''
  let result = ''

  for (const char of text) {
    if (!isLetter(char)) {
      result += char
      continue
    }
    const k =
      mode === 'autokey' && decrypt && keyIndex >= cleanKey.length
        ? letterIndex(plainHistory[keyIndex - cleanKey.length] ?? 'A')
        : letterIndex(keyStream[keyIndex % keyStream.length])
    const p = letterIndex(char)
    let c: number
    if (mode === 'vigenere') c = mod(p + (decrypt ? -k : k), 26)
    else if (mode === 'beaufort') c = mod(k - p, 26)
    else c = mod(p + (decrypt ? -k : k), 26)

    const outChar = String.fromCharCode((isUpper(char) ? 65 : 97) + c)
    result += outChar
    if (mode === 'autokey' && decrypt) plainHistory += outChar.toUpperCase()
    keyIndex++
  }
  return result
}

function affine(text: string, a: number, b: number, decrypt: boolean): string {
  const aa = mod(a, 26)
  if (gcd(aa, 26) !== 1) throw new CifraError('El multiplicador "a" debe ser coprimo con 26 (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25).')
  const inv = decrypt ? modInverseNumber(aa, 26) : 0
  return Array.from(text, (char) => {
    if (!isLetter(char)) return char
    const p = letterIndex(char)
    const value = decrypt ? mod(inv * (p - b), 26) : mod(aa * p + b, 26)
    return String.fromCharCode((isUpper(char) ? 65 : 97) + value)
  }).join('')
}

/* ----------------------------- transposición ---------------------------- */

function railFenceEncrypt(text: string, rails: number): string {
  if (rails < 2) throw new CifraError('Necesitas al menos 2 rieles.')
  if (rails > 20) throw new CifraError('Máximo 20 rieles.')
  const chars = Array.from(text)
  const rows: string[][] = Array.from({ length: rails }, () => [])
  let row = 0
  let direction = 1
  for (const char of chars) {
    rows[row].push(char)
    if (rails === 1) continue
    if (row === 0) direction = 1
    else if (row === rails - 1) direction = -1
    row += direction
  }
  return rows.map((items) => items.join('')).join('')
}

function railFenceDecrypt(text: string, rails: number): string {
  if (rails < 2) throw new CifraError('Necesitas al menos 2 rieles.')
  const chars = Array.from(text)
  const pattern: number[] = []
  let row = 0
  let direction = 1
  for (let i = 0; i < chars.length; i++) {
    pattern.push(row)
    if (row === 0) direction = 1
    else if (row === rails - 1) direction = -1
    row += direction
  }
  const counts = new Array(rails).fill(0)
  for (const r of pattern) counts[r]++
  const rows: string[][] = []
  let index = 0
  for (let r = 0; r < rails; r++) {
    rows.push(chars.slice(index, index + counts[r]))
    index += counts[r]
  }
  const pointers = new Array(rails).fill(0)
  return pattern.map((r) => rows[r][pointers[r]++]).join('')
}

function columnOrder(key: string): number[] {
  return Array.from(key)
    .map((char, index) => ({ char: char.toUpperCase(), index }))
    .sort((a, b) => (a.char === b.char ? a.index - b.index : a.char.localeCompare(b.char)))
    .map((item) => item.index)
}

function columnarEncrypt(text: string, key: string): string {
  const cleanKey = key.replace(/\s/g, '')
  if (!cleanKey) throw new CifraError('Escribe una palabra clave para las columnas.')
  const cols = cleanKey.length
  const chars = Array.from(text)
  const rows = Math.ceil(chars.length / cols)
  const order = columnOrder(cleanKey)
  let result = ''
  for (const col of order) {
    for (let r = 0; r < rows; r++) {
      const index = r * cols + col
      if (index < chars.length) result += chars[index]
    }
  }
  return result
}

function columnarDecrypt(text: string, key: string): string {
  const cleanKey = key.replace(/\s/g, '')
  if (!cleanKey) throw new CifraError('Escribe una palabra clave para las columnas.')
  const cols = cleanKey.length
  const chars = Array.from(text)
  const rows = Math.ceil(chars.length / cols)
  const order = columnOrder(cleanKey)
  const matrix: string[][] = Array.from({ length: rows }, () => new Array(cols).fill(''))
  let index = 0
  for (const col of order) {
    for (let r = 0; r < rows; r++) {
      if (r * cols + col < chars.length) matrix[r][col] = chars[index++]
    }
  }
  return matrix.flat().join('')
}

/* ------------------------------- playfair ------------------------------- */

function playfairSquare(key: string): string[][] {
  const seen = new Set<string>()
  const sequence = (lettersOnly(key) + ALPHABET.replace('J', '')).split('')
  const square: string[][] = []
  for (const char of sequence) {
    const normalized = char === 'J' ? 'I' : char
    if (seen.has(normalized)) continue
    seen.add(normalized)
    if (seen.size === 25) break
  }
  const letters = Array.from(seen)
  for (let r = 0; r < 5; r++) square.push(letters.slice(r * 5, r * 5 + 5))
  return square
}

function playfair(text: string, key: string, decrypt: boolean): string {
  const square = playfairSquare(key)
  const positions = new Map<string, [number, number]>()
  square.forEach((row, r) => row.forEach((char, c) => positions.set(char, [r, c])))
  let letters = lettersOnly(text).replace(/J/g, 'I')

  if (!decrypt) {
    let prepared = ''
    for (let i = 0; i < letters.length; i++) {
      const current = letters[i]
      const next = letters[i + 1]
      prepared += current
      if (next === current) prepared += 'X'
    }
    if (prepared.length % 2) prepared += 'X'
    letters = prepared
  }

  if (letters.length % 2) throw new CifraError('El texto cifrado Playfair debe tener una cantidad par de letras.')

  let result = ''
  for (let i = 0; i < letters.length; i += 2) {
    const a = letters[i]
    const b = letters[i + 1]
    const pa = positions.get(a)
    const pb = positions.get(b)
    if (!pa || !pb) throw new CifraError(`Letra no válida para Playfair: ${!pa ? a : b}`)
    const [ra, ca] = pa
    const [rb, cb] = pb
    if (ra === rb) {
      result += square[ra][mod(ca + (decrypt ? -1 : 1), 5)]
      result += square[rb][mod(cb + (decrypt ? -1 : 1), 5)]
    } else if (ca === cb) {
      result += square[mod(ra + (decrypt ? -1 : 1), 5)][ca]
      result += square[mod(rb + (decrypt ? -1 : 1), 5)][cb]
    } else {
      result += square[ra][cb]
      result += square[rb][ca]
    }
  }
  return result
}

/* --------------------------------- Hill --------------------------------- */

function parseMatrix(value: string, size: number): number[][] {
  const numbers = value
    .trim()
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map((item) => Number(item))
  if (numbers.length !== size * size || numbers.some((n) => !Number.isInteger(n))) {
    throw new CifraError(`La matriz debe tener ${size * size} números enteros.`)
  }
  const matrix: number[][] = []
  for (let r = 0; r < size; r++) matrix.push(numbers.slice(r * size, r * size + size).map((n) => mod(n, 26)))
  return matrix
}

function determinant2(m: number[][]): number {
  return mod(m[0][0] * m[1][1] - m[0][1] * m[1][0], 26)
}

function inverse2(m: number[][]): number[][] {
  const det = determinant2(m)
  if (gcd(det, 26) !== 1) throw new CifraError('La matriz no es invertible módulo 26.')
  const inv = modInverseNumber(det, 26)
  return [
    [mod(m[1][1] * inv, 26), mod(-m[0][1] * inv, 26)],
    [mod(-m[1][0] * inv, 26), mod(m[0][0] * inv, 26)],
  ]
}

function determinant3(m: number[][]): number {
  return mod(
    m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) -
      m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
      m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]),
    26,
  )
}

function inverse3(m: number[][]): number[][] {
  const det = determinant3(m)
  if (gcd(det, 26) !== 1) throw new CifraError('La matriz no es invertible módulo 26.')
  const inv = modInverseNumber(det, 26)
  const cofactor = (r: number, c: number): number => {
    const rows = [0, 1, 2].filter((x) => x !== r)
    const cols = [0, 1, 2].filter((x) => x !== c)
    return mod(m[rows[0]][cols[0]] * m[rows[1]][cols[1]] - m[rows[0]][cols[1]] * m[rows[1]][cols[0]], 26)
  }
  const result: number[][] = []
  for (let r = 0; r < 3; r++) {
    const row: number[] = []
    for (let c = 0; c < 3; c++) row.push(mod(cofactor(c, r) * inv, 26))
    result.push(row)
  }
  return result
}

function hill(text: string, size: number, matrixValue: string, decrypt: boolean): string {
  const matrix = parseMatrix(matrixValue, size)
  if (size !== 2 && size !== 3) throw new CifraError('Hill solo admite matrices de 2×2 o 3×3.')
  const chosen = decrypt ? (size === 2 ? inverse2(matrix) : inverse3(matrix)) : matrix
  let letters = lettersOnly(text).replace(/J/g, 'I')
  const pad = size - (letters.length % size)
  if (pad !== size) letters += 'X'.repeat(pad)
  let result = ''
  for (let offset = 0; offset < letters.length; offset += size) {
    const block = letters.slice(offset, offset + size).split('').map(letterIndex)
    for (let r = 0; r < size; r++) {
      let sum = 0
      for (let c = 0; c < size; c++) sum += chosen[r][c] * block[c]
      result += ALPHABET[mod(sum, 26)]
    }
  }
  return result
}

/* ------------------------- codificaciones varias ------------------------ */

const BACON_MAP: Record<string, string> = {}
ALPHABET.split('').forEach((char, index) => {
  BACON_MAP[char] = index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B')
})
const BACON_REVERSE = Object.fromEntries(Object.entries(BACON_MAP).map(([char, code]) => [code, char]))

function bacon(text: string, decrypt: boolean): string {
  if (decrypt) {
    const bits = text.toUpperCase().replace(/[^AB]/g, '')
    if (bits.length % 5 !== 0) throw new CifraError('La longitud en símbolos A/B debe ser múltiplo de 5.')
    let result = ''
    for (let i = 0; i < bits.length; i += 5) {
      const code = bits.slice(i, i + 5)
      const letter = BACON_REVERSE[code]
      if (!letter) throw new CifraError(`Código Bacon desconocido: ${code}`)
      result += letter
    }
    return result
  }
  const letters = lettersOnly(text).replace(/J/g, 'I')
  return letters
    .split('')
    .map((char) => BACON_MAP[char])
    .join(' ')
}

const MORSE: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
  K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
  U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..', '0': '-----', '1': '.----', '2': '..---',
  '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
  '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
  '"': '.-..-.', '@': '.--.-.', "'": '.----.', Ñ: '--.--',
}
const MORSE_REVERSE = Object.fromEntries(Object.entries(MORSE).map(([char, code]) => [code, char]))

function morse(text: string, decrypt: boolean): string {
  if (decrypt) {
    return text
      .trim()
      .split(/\s*\/\s*/)
      .map((word) =>
        word
          .trim()
          .split(/\s+/)
          .filter(Boolean)
          .map((code) => MORSE_REVERSE[code] ?? '?')
          .join(''),
      )
      .join(' ')
  }
  return Array.from(text.toUpperCase(), (char) => {
    if (char === ' ') return '/'
    return MORSE[char] ?? ''
  })
    .filter(Boolean)
    .join(' ')
}

function xorText(text: string, key: string, decrypt: boolean): string {
  if (!key) throw new CifraError('Escribe una clave para XOR.')
  const keyBytes = utf8ToBytes(key)
  const data = decrypt ? fromHex(text) : utf8ToBytes(text)
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ keyBytes[i % keyBytes.length]
  return decrypt ? bytesToUtf8(out) : toHex(out)
}

function vernam(text: string, keyHex: string, decrypt: boolean): string {
  const key = fromHex(keyHex)
  if (!key.length) throw new CifraError('Falta la clave de un solo uso en hexadecimal.')
  const data = decrypt ? fromHex(text) : utf8ToBytes(text)
  if (key.length !== data.length) {
    throw new CifraError(`La clave debe medir exactamente ${data.length} bytes (${data.length * 2} hex).`)
  }
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i]
  return decrypt ? bytesToUtf8(out) : toHex(out)
}

function a1z26(text: string, decrypt: boolean): string {
  if (decrypt) {
    const tokens = text.split(/[^0-9]+/).filter(Boolean)
    if (!tokens.length) throw new CifraError('Escribe números A1Z26 para decodificar.')
    return tokens
      .map((token) => {
        const n = Number(token)
        if (n < 1 || n > 26) throw new CifraError(`Número fuera de rango A1Z26: ${token}`)
        return ALPHABET[n - 1]
      })
      .join('')
  }
  return lettersOnly(text)
    .split('')
    .map((char) => letterIndex(char) + 1)
    .join(' ')
}

function binaryEncode(text: string): string {
  return Array.from(utf8ToBytes(text), (byte) => byte.toString(2).padStart(8, '0')).join(' ')
}

function binaryDecode(text: string): string {
  const groups = text.trim().split(/\s+/).filter(Boolean)
  if (!groups.length || groups.some((group) => !/^[01]{8}$/.test(group))) {
    throw new CifraError('El binario debe contener grupos de 8 bits (0/1) separados por espacios.')
  }
  return bytesToUtf8(Uint8Array.from(groups.map((group) => parseInt(group, 2))))
}

export function runClassic(
  id: ClassicId,
  decrypt: boolean,
  text: string,
  params: Record<string, string>,
): string {
  const alg = classicById(id)
  if (!text.trim() && alg.family !== 'Codificación') {
    throw new CifraError('Escribe el texto que quieres procesar.')
  }
  switch (id) {
    case 'cesar': {
      const shift = Number(params.shift ?? 3)
      if (!Number.isInteger(shift)) throw new CifraError('El desplazamiento debe ser un número entero.')
      return cesar(text, decrypt ? -shift : shift)
    }
    case 'rot13':
      return cesar(text, 13)
    case 'rot47':
      return rot47(text)
    case 'atbash':
      return atbash(text)
    case 'vigenere':
      return polyalphabetic(text, params.key ?? '', 'vigenere', decrypt)
    case 'beaufort':
      return polyalphabetic(text, params.key ?? '', 'beaufort', decrypt)
    case 'autoclave':
      return polyalphabetic(text, params.key ?? '', 'autokey', decrypt)
    case 'afin':
      return affine(text, Number(params.a ?? 5), Number(params.b ?? 8), decrypt)
    case 'railfence': {
      const rails = Number(params.rails ?? 3)
      return decrypt ? railFenceDecrypt(text, rails) : railFenceEncrypt(text, rails)
    }
    case 'columnar':
      return decrypt ? columnarDecrypt(text, params.key ?? '') : columnarEncrypt(text, params.key ?? '')
    case 'playfair':
      return playfair(text, params.key ?? '', decrypt)
    case 'hill':
      return hill(text, Number(params.matrixSize ?? 2), params.matrix ?? '', decrypt)
    case 'bacon':
      return bacon(text, decrypt)
    case 'morse':
      return morse(text, decrypt)
    case 'xor':
      return xorText(text, params.key ?? '', decrypt)
    case 'vernam':
      return vernam(text, params.otpKey ?? '', decrypt)
    case 'base64':
      return decrypt ? bytesToUtf8(fromBase64(text)) : toBase64(utf8ToBytes(text))
    case 'base64url':
      return decrypt ? bytesToUtf8(fromBase64Url(text)) : toBase64Url(utf8ToBytes(text))
    case 'hex':
      return decrypt ? bytesToUtf8(fromHex(text)) : toHex(utf8ToBytes(text))
    case 'binario':
      return decrypt ? binaryDecode(text) : binaryEncode(text)
    case 'a1z26':
      return a1z26(text, decrypt)
    case 'url':
      return decrypt ? decodeURIComponent(text) : encodeURIComponent(text)
    default:
      throw new CifraError('Algoritmo no soportado.')
  }
}

export function generateOtp(length: number): string {
  return toHex(randomBytes(Math.max(1, length)))
}
