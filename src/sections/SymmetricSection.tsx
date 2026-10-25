import { useState } from 'react'
import {
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LockKeyhole,
  RefreshCw,
  Unlock,
  WandSparkles,
} from 'lucide-react'
import {
  Alert,
  AlgorithmCard,
  Badge,
  Button,
  OutputBox,
  Panel,
  Segmented,
  SectionHeader,
  SelectField,
  TextAreaField,
  TextField,
} from '../components/ui'
import {
  decryptSymmetric,
  describeSecret,
  encryptSymmetric,
  passwordStrength,
  randomKeyHex,
  SYMMETRIC_ALGORITHMS,
  symById,
  type SymId,
} from '../lib/symmetric'
import { DEFAULT_PBKDF2_ITERATIONS } from '../lib/kdf'
import { formatError } from '../lib/bytes'

type Mode = 'encrypt' | 'decrypt'
type SecretMode = 'password' | 'raw'

type Result = {
  value: string
  label: string
  algorithm: string
  keyBytes: number
  bytes: number
  kdf: string
  mode: Mode
}

export default function SymmetricSection() {
  const [algId, setAlgId] = useState<SymId>('AES-GCM')
  const [mode, setMode] = useState<Mode>('encrypt')
  const [secretMode, setSecretMode] = useState<SecretMode>('password')
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [plaintext, setPlaintext] = useState('')
  const [ciphertext, setCiphertext] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [error, setError] = useState('')
  const [keyBits, setKeyBits] = useState<128 | 192 | 256>(256)
  const [iterations, setIterations] = useState(String(DEFAULT_PBKDF2_ITERATIONS))

  const algorithm = symById(algId)
  const isAes = algId.startsWith('AES-')
  const keyLength = isAes ? keyBits / 8 : algorithm.keyLengths[0]
  const strength = passwordStrength(secret)
  const levelTone =
    algorithm.level === 'recomendado'
      ? 'success'
      : algorithm.level === 'aceptable'
        ? 'warn'
        : 'danger'

  const resetOutput = () => {
    setResult(null)
    setError('')
  }

  const selectAlgorithm = (id: SymId) => {
    setAlgId(id)
    setError('')
    setResult(null)
  }

  const handleRun = () => {
    setError('')
    setResult(null)
    try {
      if (mode === 'encrypt') {
        const encrypted = encryptSymmetric({
          alg: algId,
          plaintext,
          secret,
          secretMode,
          keyBits: isAes ? keyBits : undefined,
          iterations: secretMode === 'password' ? Number(iterations) : undefined,
        })
        setCiphertext(encrypted.payload)
        setResult({
          value: encrypted.payload,
          label: 'Paquete cifrado',
          algorithm: encrypted.algorithm.id,
          keyBytes: encrypted.keyBytes,
          bytes: encrypted.bytes,
          kdf: encrypted.derived
            ? `PBKDF2 · ${Number(iterations).toLocaleString('es')} iteraciones`
            : 'Clave cruda',
          mode: 'encrypt',
        })
      } else {
        const decrypted = decryptSymmetric(ciphertext, secret, secretMode)
        setPlaintext(decrypted.plaintext)
        setResult({
          value: decrypted.plaintext,
          label: 'Texto descifrado',
          algorithm: decrypted.algorithm.id,
          keyBytes: decrypted.keyBytes,
          bytes: decrypted.bytes,
          kdf: secretMode === 'password' ? 'PBKDF2-SHA256' : 'Clave cruda',
          mode: 'decrypt',
        })
      }
    } catch (caught) {
      setError(formatError(caught))
    }
  }

  const generateKey = () => {
    const value = randomKeyHex(keyLength)
    setSecret(value)
    setSecretMode('raw')
    setShowSecret(true)
  }

  const testDecrypt = () => {
    if (!result) return
    setCiphertext(result.value)
    setMode('decrypt')
    setError('')
  }

  const handleMode = (next: Mode) => {
    setMode(next)
    setError('')
    if (next === 'decrypt' && plaintext) {
      setCiphertext((current) => current || '')
    }
    if (next === 'encrypt' && !plaintext && result?.mode === 'decrypt') {
      setPlaintext(result.value)
    }
  }

  return (
    <div className="section">
      <SectionHeader
        title="Cifrado simétrico"
        lead="La misma contraseña o clave cifra y descifra el mensaje."
      />

      <Panel title="Algoritmo" icon={LockKeyhole} className="algo-panel">
        <div className="algo-grid algo-grid-wide">
          {SYMMETRIC_ALGORITHMS.map((item) => (
            <AlgorithmCard
              key={item.id}
              name={item.id}
              meta={item.tagline}
              selected={item.id === algId}
              onClick={() => selectAlgorithm(item.id)}
              tone={
                item.level === 'inseguro'
                  ? 'danger'
                  : item.level === 'obsoleto'
                    ? 'warn'
                    : 'neutral'
              }
            />
          ))}
        </div>
      </Panel>

      <div className="tool-grid">
        <Panel
          title={mode === 'encrypt' ? 'Cifrar mensaje' : 'Descifrar paquete'}
          subtitle={`${algorithm.id} · ${algorithm.tagline}`}
          icon={mode === 'encrypt' ? Lock : Unlock}
          actions={
            <Segmented
              label="Acción"
              value={mode}
              onChange={handleMode}
              options={[
                { value: 'encrypt', label: 'Cifrar', icon: Lock },
                { value: 'decrypt', label: 'Descifrar', icon: Unlock },
              ]}
            />
          }
        >
          <div className="form-stack">
            <Segmented
              label="Tipo de secreto"
              value={secretMode}
              onChange={(next) => {
                setSecretMode(next)
                setError('')
              }}
              options={[
                { value: 'password', label: 'Contraseña', icon: KeyRound },
                { value: 'raw', label: 'Clave hex', icon: WandSparkles },
              ]}
            />

            <TextField
              label={secretMode === 'password' ? 'Contraseña' : `Clave hexadecimal (${keyLength} bytes)`}
              type={showSecret ? 'text' : 'password'}
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
              placeholder={
                secretMode === 'password'
                  ? 'Escribe una contraseña'
                  : `${keyLength * 2} caracteres hexadecimales`
              }
              autoComplete="new-password"
              spellCheck={false}
              className={secretMode === 'raw' ? 'mono-input' : ''}
              hint={
                secretMode === 'password'
                  ? 'Se deriva con PBKDF2-SHA256 y una sal aleatoria.'
                  : `Se usa directamente. ${describeSecret(secret, secretMode)}.`
              }
              action={
                <div className="field-actions">
                  {secretMode === 'raw' ? (
                    <button type="button" className="link-btn" onClick={generateKey}>
                      <WandSparkles size={13} /> Generar
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="link-btn"
                    onClick={() => setShowSecret((value) => !value)}
                    aria-label={showSecret ? 'Ocultar secreto' : 'Mostrar secreto'}
                  >
                    {showSecret ? <EyeOff size={13} /> : <Eye size={13} />}
                    {showSecret ? 'Ocultar' : 'Ver'}
                  </button>
                </div>
              }
            />

            {secretMode === 'password' && mode === 'encrypt' ? (
              <div className={`pw-meter ${secret ? `pw-${strength}` : ''}`} aria-hidden="true">
                {[0, 1, 2, 3].map((index) => (
                  <span key={index} className={index < strength ? 'is-on' : ''} />
                ))}
                <em>
                  {!secret
                    ? 'Sin contraseña'
                    : ['Muy débil', 'Débil', 'Aceptable', 'Fuerte', 'Excelente'][strength]}
                </em>
              </div>
            ) : null}

            {mode === 'encrypt' ? (
              <TextAreaField
                label="Texto a cifrar"
                value={plaintext}
                onChange={(event) => setPlaintext(event.target.value)}
                placeholder="Escribe el mensaje"
                rows={7}
                hint={`${plaintext.length} caracteres`}
              />
            ) : (
              <TextAreaField
                label="Paquete cifrado"
                value={ciphertext}
                onChange={(event) => setCiphertext(event.target.value)}
                placeholder="CIFRA1.eyJ2Ijox…"
                rows={7}
                mono
                hint="Acepta paquetes CIFRA1, JSON o base64 de JSON."
              />
            )}

            <details className="details">
              <summary>Opciones avanzadas</summary>
              <div className="details-body form-grid">
                {isAes ? (
                  <SelectField
                    label="Tamaño de clave AES"
                    value={String(keyBits)}
                    onChange={(event) => setKeyBits(Number(event.target.value) as 128 | 192 | 256)}
                  >
                    <option value="128">128 bits</option>
                    <option value="192">192 bits</option>
                    <option value="256">256 bits</option>
                  </SelectField>
                ) : (
                  <div className="mini-note">
                    <span>Clave del algoritmo</span>
                    <strong>{keyLength * 8} bits fijos</strong>
                  </div>
                )}
                {secretMode === 'password' ? (
                  <TextField
                    label="Iteraciones PBKDF2"
                    type="number"
                    min={10000}
                    max={2000000}
                    step={1000}
                    value={iterations}
                    onChange={(event) => setIterations(event.target.value)}
                  />
                ) : (
                  <div className="mini-note">
                    <span>Derivación</span>
                    <strong>Sin KDF · clave directa</strong>
                  </div>
                )}
              </div>
            </details>

            {algorithm.warning ? (
              <Alert tone={algorithm.level === 'inseguro' ? 'danger' : 'warn'}>
                {algorithm.warning}
              </Alert>
            ) : null}

            {error ? (
              <Alert tone="danger" title="No se pudo completar">
                {error}
              </Alert>
            ) : null}

            <div className="form-actions">
              <Button
                icon={mode === 'encrypt' ? Lock : Unlock}
                onClick={handleRun}
                size="lg"
                disabled={!secret || (mode === 'encrypt' ? !plaintext : !ciphertext)}
              >
                {mode === 'encrypt' ? 'Cifrar mensaje' : 'Descifrar paquete'}
              </Button>
              <Button
                variant="ghost"
                icon={RefreshCw}
                onClick={() => {
                  setSecret('')
                  setPlaintext('')
                  setCiphertext('')
                  resetOutput()
                }}
              >
                Limpiar
              </Button>
            </div>
          </div>
        </Panel>

        <div className="side-stack">
          <Panel title="Resultado" icon={LockKeyhole}>
            {result ? (
              <>
                <OutputBox
                  value={result.value}
                  label={result.label}
                  rows={9}
                  tone={result.mode === 'decrypt' ? 'success' : 'neutral'}
                  filename={`resultado-${result.algorithm.toLowerCase()}.txt`}
                />
                <div className="result-meta">
                  <span>
                    <em>Algoritmo</em>
                    <strong>{result.algorithm}</strong>
                  </span>
                  <span>
                    <em>Clave</em>
                    <strong>{result.keyBytes * 8} bits</strong>
                  </span>
                  <span>
                    <em>Criptograma</em>
                    <strong>{result.bytes} bytes</strong>
                  </span>
                  <span>
                    <em>Derivación</em>
                    <strong>{result.kdf}</strong>
                  </span>
                </div>
                {result.mode === 'encrypt' && secret ? (
                  <Button variant="soft" size="sm" icon={Unlock} onClick={testDecrypt}>
                    Probar a descifrar
                  </Button>
                ) : null}
              </>
            ) : (
              <div className="result-placeholder">
                <Lock size={20} />
                <strong>Sin resultado</strong>
                <p>Completa el formulario y pulsa el botón para ver el resultado.</p>
              </div>
            )}
          </Panel>

          <div className="algorithm-note">
            <span>Nivel</span>
            <Badge tone={levelTone}>{algorithm.level}</Badge>
            <span>Clave</span>
            <strong>{algorithm.keyLengths.map((length) => length * 8).join(' / ')} bits</strong>
          </div>
        </div>
      </div>
    </div>
  )
}
