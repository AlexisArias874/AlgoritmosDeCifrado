import { useState } from 'react'
import { Info, KeyRound, Lock, RefreshCw, ScrollText, Unlock } from 'lucide-react'
import {
  Alert,
  AlgorithmCard,
  Button,
  OutputBox,
  Panel,
  SectionHeader,
  Segmented,
  SelectField,
  TextAreaField,
  TextField,
} from '../components/ui'
import {
  CLASSIC_ALGORITHMS,
  classicById,
  generateOtp,
  runClassic,
  type ClassicId,
} from '../lib/classic'
import { formatError, utf8ToBytes } from '../lib/bytes'

type Mode = 'encrypt' | 'decrypt'
type Family = 'Todos' | 'Sustitución' | 'Transposición' | 'Poligráfico' | 'Codificación' | 'Flujo'

const FAMILIES: Family[] = [
  'Todos',
  'Sustitución',
  'Transposición',
  'Poligráfico',
  'Codificación',
  'Flujo',
]

const LOSSY: ClassicId[] = ['playfair', 'hill', 'bacon', 'a1z26']

const defaultsFor = (id: ClassicId): Record<string, string> => {
  const algorithm = classicById(id)
  return Object.fromEntries(algorithm.fields.map((field) => [field.name, field.defaultValue]))
}

const HINTS: Partial<Record<ClassicId, string>> = {
  cesar: 'Solo hay 25 desplazamientos posibles.',
  vigenere: 'La clave se repite a lo largo del mensaje.',
  autoclave: 'La clave inicial se continúa con el texto claro.',
  afin: 'La "a" debe ser coprima con 26 para poder descifrar.',
  playfair: 'La J se combina con la I; los pares repetidos se separan con X.',
  hill: 'La matriz se aplica a bloques; el determinante debe ser coprimo con 26.',
  bacon: 'No conserva espacios, tildes ni signos.',
  morse: 'Los espacios separan letras y la barra "/" separa palabras.',
  xor: 'Demostración educativa; no es un cifrado seguro.',
  vernam: 'La clave debe ser aleatoria, secreta y de un solo uso.',
}

export default function ClassicSection() {
  const [algId, setAlgId] = useState<ClassicId>('cesar')
  const [family, setFamily] = useState<Family>('Todos')
  const [mode, setMode] = useState<Mode>('encrypt')
  const [text, setText] = useState('')
  const [params, setParams] = useState<Record<string, string>>(() => defaultsFor('cesar'))
  const [result, setResult] = useState('')
  const [error, setError] = useState('')

  const algorithm = classicById(algId)
  const visible = CLASSIC_ALGORITHMS.filter((item) => family === 'Todos' || item.family === family)
  const tone =
    algorithm.level === 'débil'
      ? 'danger'
      : algorithm.level === 'educativo'
        ? 'warn'
        : 'neutral'

  const selectAlgorithm = (id: ClassicId) => {
    setAlgId(id)
    setParams(defaultsFor(id))
    setResult('')
    setError('')
  }

  const updateParam = (name: string, value: string) => {
    setParams((current) => {
      const next = { ...current, [name]: value }
      if (name === 'matrixSize') {
        next.matrix = value === '3' ? '6 24 1 13 16 10 20 17 15' : '3 3 2 5'
      }
      return next
    })
  }

  const run = () => {
    setError('')
    try {
      setResult(runClassic(algId, mode === 'decrypt', text, params))
    } catch (caught) {
      setResult('')
      setError(formatError(caught))
    }
  }

  const handleMode = (next: Mode) => {
    setMode(next)
    setError('')
    if (next === 'decrypt' && result) setText(result)
    if (next === 'encrypt' && result) setText(result)
    setResult('')
  }

  const generateOtpKey = () => {
    const length =
      mode === 'encrypt'
        ? utf8ToBytes(text).length
        : Math.max(1, text.replace(/\s/g, '').length / 2)
    if (!length || !Number.isFinite(length)) {
      setError('Escribe primero el texto para calcular el tamaño de la clave.')
      return
    }
    updateParam('otpKey', generateOtp(length))
    setError('')
  }

  return (
    <div className="section">
      <SectionHeader
        title="Cifrados clásicos"
        lead="Métodos históricos de sustitución, transposición y codificación."
      />

      <Panel title="Método" icon={ScrollText} className="algo-panel">
        <div className="filter-row">
          {FAMILIES.map((item) => (
            <button
              key={item}
              type="button"
              className={`filter-chip ${family === item ? 'is-active' : ''}`}
              onClick={() => setFamily(item)}
            >
              {item}
            </button>
          ))}
        </div>
        <div className="algo-grid algo-grid-wide">
          {visible.map((item) => (
            <AlgorithmCard
              key={item.id}
              name={item.name}
              meta={item.family}
              selected={item.id === algId}
              onClick={() => selectAlgorithm(item.id)}
              tone={
                item.level === 'débil'
                  ? 'danger'
                  : item.level === 'educativo'
                    ? 'warn'
                    : 'neutral'
              }
            />
          ))}
        </div>
      </Panel>

      <div className="tool-grid tool-grid-single">
        <Panel
          title={`${mode === 'encrypt' ? 'Cifrar' : 'Descifrar'} · ${algorithm.name}`}
          subtitle={algorithm.description}
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
            {algorithm.fields.length ? (
              <div className="form-grid">
                {algorithm.fields.map((field) => {
                  if (field.kind === 'select') {
                    return (
                      <SelectField
                        key={field.name}
                        label={field.label}
                        value={params[field.name] ?? field.defaultValue}
                        onChange={(event) => updateParam(field.name, event.target.value)}
                        hint={field.help}
                      >
                        {field.options?.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </SelectField>
                    )
                  }
                  if (field.kind === 'number') {
                    return (
                      <TextField
                        key={field.name}
                        label={field.label}
                        type="number"
                        value={params[field.name] ?? field.defaultValue}
                        onChange={(event) => updateParam(field.name, event.target.value)}
                        hint={field.help}
                      />
                    )
                  }
                  return (
                    <TextField
                      key={field.name}
                      label={field.label}
                      value={params[field.name] ?? field.defaultValue}
                      onChange={(event) => updateParam(field.name, event.target.value)}
                      placeholder={field.placeholder}
                      hint={field.help}
                      spellCheck={false}
                      className={field.mono || algId === 'vernam' ? 'mono-input' : ''}
                      action={
                        algId === 'vernam' ? (
                          <button type="button" className="link-btn" onClick={generateOtpKey}>
                            <KeyRound size={13} /> Generar
                          </button>
                        ) : undefined
                      }
                    />
                  )
                })}
              </div>
            ) : (
              <div className="mini-note">
                <span>Parámetros</span>
                <strong>Este método no necesita configuración</strong>
              </div>
            )}

            <TextAreaField
              label={mode === 'encrypt' ? 'Texto original' : 'Texto cifrado'}
              value={text}
              onChange={(event) => {
                setText(event.target.value)
                setError('')
              }}
              placeholder={
                mode === 'encrypt' ? 'Escribe el mensaje' : 'Pega el resultado que quieres descifrar'
              }
              rows={7}
              mono={mode === 'decrypt' && ['xor', 'vernam', 'hex', 'binario'].includes(algId)}
              hint={
                LOSSY.includes(algId)
                  ? 'Este método conserva solo letras A–Z; se pierden espacios, tildes, números y signos.'
                  : `${text.length} caracteres`
              }
            />

            {HINTS[algId] ? (
              <div className="hint-line">
                <Info size={14} />
                {HINTS[algId]}
              </div>
            ) : null}

            {error ? (
              <Alert tone="danger" title="No se pudo procesar">
                {error}
              </Alert>
            ) : null}

            <div className="form-actions">
              <Button
                size="lg"
                icon={mode === 'encrypt' ? Lock : Unlock}
                onClick={run}
                disabled={!text.trim() && algorithm.family !== 'Codificación'}
              >
                {mode === 'encrypt' ? 'Transformar texto' : 'Recuperar texto'}
              </Button>
              <Button
                variant="ghost"
                icon={RefreshCw}
                onClick={() => {
                  setText('')
                  setResult('')
                  setError('')
                  setParams(defaultsFor(algId))
                }}
              >
                Limpiar
              </Button>
            </div>

            {result ? (
              <>
                <OutputBox
                  value={result}
                  label={mode === 'encrypt' ? 'Texto cifrado' : 'Texto recuperado'}
                  rows={7}
                  tone={mode === 'decrypt' ? 'success' : 'neutral'}
                  filename={`resultado-${algId}.txt`}
                />
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setText(result)
                    setMode(mode === 'encrypt' ? 'decrypt' : 'encrypt')
                    setResult('')
                    setError('')
                  }}
                >
                  Usar el resultado como entrada
                </Button>
              </>
            ) : null}
          </div>
        </Panel>
      </div>

      {tone === 'danger' ? (
        <div className="section-footnote">
          <Info size={14} />
          Este método no protege secretos reales. Se incluye con fines educativos.
        </div>
      ) : null}
    </div>
  )
}
