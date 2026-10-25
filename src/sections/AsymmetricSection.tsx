import { useState } from 'react'
import {
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LockOpen,
  ShieldCheck,
  TriangleAlert,
  Unlock,
  Upload,
} from 'lucide-react'
import {
  Alert,
  AlgorithmCard,
  Badge,
  Button,
  KeyValue,
  OutputBox,
  Panel,
  Segmented,
  SectionHeader,
  SelectField,
  TextAreaField,
  EmptyState,
  Spinner,
} from '../components/ui'
import { downloadText, formatError } from '../lib/bytes'
import {
  ecFingerprint,
  eciesDecrypt,
  eciesEncrypt,
  elgamalDecrypt,
  elgamalEncrypt,
  elgamalFingerprint,
  generateEcKeyPair,
  generateElGamalKeyPair,
  generateRsaKeyPair,
  rsaDecrypt,
  rsaEncrypt,
  rsaFingerprint,
  safeJsonParse,
  type EcKeyBundle,
  type ElGamalKeyBundle,
  type RsaKeyBundle,
} from '../lib/asymmetric'
import { hexPreview } from '../lib/dh'

type Alg = 'RSA' | 'ECIES' | 'ELGAMAL'
type Mode = 'encrypt' | 'decrypt'
type RsaMode = 'hybrid' | 'direct'

type Result = {
  value: string
  label: string
  algorithm: string
  detail: string
  mode: Mode
}

const ALGORITHMS: {
  id: Alg
  name: string
  meta: string
  label: string
}[] = [
  {
    id: 'RSA',
    name: 'RSA-OAEP',
    meta: '2048 · 3072 · 4096 bits',
    label: 'RSA',
  },
  {
    id: 'ECIES',
    name: 'ECIES P-256',
    meta: 'Curva elíptica · 256 bits',
    label: 'ECC',
  },
  {
    id: 'ELGAMAL',
    name: 'ElGamal 2048',
    meta: 'Grupo MODP · 2048 bits',
    label: 'ElGamal',
  },
]

export default function AsymmetricSection() {
  const [alg, setAlg] = useState<Alg>('RSA')
  const [mode, setMode] = useState<Mode>('encrypt')
  const [rsa, setRsa] = useState<RsaKeyBundle | null>(null)
  const [ec, setEc] = useState<EcKeyBundle | null>(null)
  const [elgamal, setElgamal] = useState<ElGamalKeyBundle | null>(null)
  const [rsaBits, setRsaBits] = useState(2048)
  const [rsaMode, setRsaMode] = useState<RsaMode>('hybrid')
  const [plaintext, setPlaintext] = useState('')
  const [payload, setPayload] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [showPrivate, setShowPrivate] = useState(false)

  const current = ALGORITHMS.find((item) => item.id === alg)!
  const activeBundle = alg === 'RSA' ? rsa : alg === 'ECIES' ? ec : elgamal
  const publicKey =
    alg === 'RSA' ? rsa?.publicKey : alg === 'ECIES' ? ec?.publicKey : elgamal?.publicKey
  const privateKey =
    alg === 'RSA' ? rsa?.privateKey : alg === 'ECIES' ? ec?.secretKey : elgamal?.secretKey
  const fingerprint =
    alg === 'RSA' && rsa
      ? rsaFingerprint(rsa)
      : alg === 'ECIES' && ec
        ? ecFingerprint(ec)
        : alg === 'ELGAMAL' && elgamal
          ? elgamalFingerprint(elgamal)
          : ''

  const publicBundle = (): string | null => {
    if (alg === 'RSA' && rsa) {
      return JSON.stringify(
        { alg: 'RSA-OAEP', bits: rsa.bits, publicKey: rsa.publicKey, createdAt: rsa.createdAt },
        null,
        2,
      )
    }
    if (alg === 'ECIES' && ec) {
      return JSON.stringify(
        { alg: 'ECIES-P256', publicKey: ec.publicKey, createdAt: ec.createdAt },
        null,
        2,
      )
    }
    if (alg === 'ELGAMAL' && elgamal) {
      return JSON.stringify(
        {
          alg: 'ELGAMAL-2048',
          publicKey: elgamal.publicKey,
          group: elgamal.group,
          createdAt: elgamal.createdAt,
        },
        null,
        2,
      )
    }
    return null
  }

  const privateBundle = (): string | null => {
    if (!activeBundle) return null
    return JSON.stringify(activeBundle, null, 2)
  }

  const generateKeys = async () => {
    setBusy(true)
    setError('')
    try {
      if (alg === 'RSA') {
        setRsa(await generateRsaKeyPair(rsaBits))
      } else if (alg === 'ECIES') {
        setEc(generateEcKeyPair())
      } else {
        setElgamal(generateElGamalKeyPair())
      }
      setResult(null)
      setShowPrivate(false)
    } catch (caught) {
      setError(formatError(caught))
    } finally {
      setBusy(false)
    }
  }

  const importBundle = () => {
    setError('')
    try {
      const data = safeJsonParse<Record<string, unknown>>(importText, 'la clave')
      if (data.alg === 'RSA-OAEP' && data.publicKey) {
        setRsa({
          alg: 'RSA-OAEP',
          bits: Number(data.bits ?? 2048),
          publicKey: data.publicKey as JsonWebKey,
          privateKey: data.privateKey as JsonWebKey,
          createdAt: Number(data.createdAt ?? Date.now()),
        })
        setAlg('RSA')
      } else if (data.alg === 'ECIES-P256' && typeof data.publicKey === 'string') {
        setEc({
          alg: 'ECIES-P256',
          publicKey: data.publicKey,
          secretKey: typeof data.secretKey === 'string' ? data.secretKey : '',
          createdAt: Number(data.createdAt ?? Date.now()),
        })
        setAlg('ECIES')
      } else if (data.alg === 'ELGAMAL-2048' && typeof data.publicKey === 'string') {
        setElgamal({
          alg: 'ELGAMAL-2048',
          publicKey: data.publicKey,
          secretKey: typeof data.secretKey === 'string' ? data.secretKey : '',
          group: String(data.group ?? 'MODP-2048 (RFC 3526) · g = 2'),
          createdAt: Number(data.createdAt ?? Date.now()),
        })
        setAlg('ELGAMAL')
      } else {
        throw new Error('El JSON no corresponde a un par de claves válido.')
      }
      setImportOpen(false)
      setImportText('')
      setResult(null)
    } catch (caught) {
      setError(formatError(caught))
    }
  }

  const run = async () => {
    setError('')
    setResult(null)
    try {
      let value = ''
      let label = ''
      let detail = ''
      if (alg === 'RSA') {
        if (!rsa) throw new Error('Genera o importa un par de claves RSA primero.')
        if (mode === 'encrypt') {
          if (!rsa.publicKey) throw new Error('La clave importada no incluye clave pública.')
          value = await rsaEncrypt(plaintext, rsa.publicKey, rsaMode)
          label = 'Paquete RSA'
          detail = rsaMode === 'hybrid' ? 'Híbrido · RSA-OAEP + AES-256-GCM' : 'RSA-OAEP directo'
        } else {
          if (!rsa.privateKey) throw new Error('Necesitas la clave privada para descifrar.')
          value = await rsaDecrypt(payload, rsa.privateKey)
          label = 'Texto descifrado'
          detail = `RSA-${rsa.bits}`
        }
      } else if (alg === 'ECIES') {
        if (!ec) throw new Error('Genera o importa un par de claves ECC primero.')
        if (mode === 'encrypt') {
          if (!ec.publicKey) throw new Error('La clave importada no incluye clave pública.')
          value = eciesEncrypt(plaintext, ec.publicKey)
          label = 'Paquete ECIES'
          detail = 'ECDH P-256 + HKDF + AES-256-GCM'
        } else {
          if (!ec.secretKey) throw new Error('Necesitas la clave privada ECC para descifrar.')
          value = eciesDecrypt(payload, ec.secretKey)
          label = 'Texto descifrado'
          detail = 'ECIES P-256'
        }
      } else {
        if (!elgamal) throw new Error('Genera o importa un par de claves ElGamal primero.')
        if (mode === 'encrypt') {
          if (!elgamal.publicKey) throw new Error('La clave importada no incluye clave pública.')
          value = elgamalEncrypt(plaintext, elgamal.publicKey)
          label = 'Paquete ElGamal'
          detail = 'ElGamal 2048 + AES-256-GCM'
        } else {
          if (!elgamal.secretKey) throw new Error('Necesitas la clave privada ElGamal para descifrar.')
          value = elgamalDecrypt(payload, elgamal.secretKey)
          label = 'Texto descifrado'
          detail = 'ElGamal 2048'
        }
      }
      setResult({ value, label, algorithm: current.name, detail, mode })
      if (mode === 'encrypt') setPayload(value)
    } catch (caught) {
      setError(formatError(caught))
    }
  }

  const handleAlg = (next: Alg) => {
    setAlg(next)
    setError('')
    setResult(null)
    setMode('encrypt')
  }

  return (
    <div className="section">
      <SectionHeader
        title="Cifrado asimétrico"
        lead="La clave pública cifra; solo la clave privada correspondiente puede descifrar."
      />

      <Panel title="Algoritmo" icon={KeyRound} className="algo-panel">
        <div className="algo-grid algo-grid-three">
          {ALGORITHMS.map((item) => (
            <AlgorithmCard
              key={item.id}
              name={item.name}
              meta={item.meta}
              selected={item.id === alg}
              onClick={() => handleAlg(item.id)}
            />
          ))}
        </div>
      </Panel>

      <div className="tool-grid">
        <Panel
          title={mode === 'encrypt' ? 'Cifrar con clave pública' : 'Descifrar con clave privada'}
          subtitle={current.name}
          icon={mode === 'encrypt' ? Lock : Unlock}
          actions={
            <Segmented
              label="Acción"
              value={mode}
              onChange={(next) => {
                setMode(next)
                setError('')
              }}
              options={[
                { value: 'encrypt', label: 'Cifrar', icon: Lock },
                { value: 'decrypt', label: 'Descifrar', icon: Unlock },
              ]}
            />
          }
        >
          <div className="form-stack">
            {alg === 'RSA' ? (
              <div className="form-grid">
                <SelectField
                  label="Modo de cifrado"
                  value={rsaMode}
                  onChange={(event) => setRsaMode(event.target.value as RsaMode)}
                  hint={
                    rsaMode === 'hybrid'
                      ? 'RSA protege una clave AES; sirve para cualquier longitud.'
                      : 'Solo textos cortos (máx. ~190 bytes con RSA-2048).'
                  }
                >
                  <option value="hybrid">Híbrido</option>
                  <option value="direct">RSA directo</option>
                </SelectField>
                <SelectField
                  label="Tamaño de clave RSA"
                  value={String(rsaBits)}
                  onChange={(event) => setRsaBits(Number(event.target.value))}
                  hint="Cambiarlo requiere regenerar el par."
                >
                  <option value="2048">2048 bits</option>
                  <option value="3072">3072 bits</option>
                  <option value="4096">4096 bits</option>
                </SelectField>
              </div>
            ) : null}

            {mode === 'encrypt' ? (
              <TextAreaField
                label="Texto a cifrar"
                value={plaintext}
                onChange={(event) => setPlaintext(event.target.value)}
                placeholder="Escribe el mensaje"
                rows={8}
                hint={`${plaintext.length} caracteres`}
              />
            ) : (
              <TextAreaField
                label="Paquete cifrado"
                value={payload}
                onChange={(event) => setPayload(event.target.value)}
                placeholder="CIFRA1.eyJ2Ijox…"
                rows={8}
                mono
                hint="Pega el paquete generado con la clave pública de este par."
              />
            )}

            {error ? (
              <Alert tone="danger" title="No se pudo completar">
                {error}
              </Alert>
            ) : null}

            <div className="form-actions">
              <Button
                icon={mode === 'encrypt' ? Lock : Unlock}
                size="lg"
                onClick={run}
                disabled={!activeBundle || (mode === 'encrypt' ? !plaintext : !payload)}
              >
                {mode === 'encrypt' ? `Cifrar con ${current.label}` : 'Descifrar paquete'}
              </Button>
              {!activeBundle ? (
                <span className="inline-hint">
                  <TriangleAlert size={14} /> Genera un par de claves para continuar.
                </span>
              ) : null}
            </div>

            {result ? (
              <>
                <OutputBox
                  value={result.value}
                  label={result.label}
                  rows={9}
                  tone={result.mode === 'decrypt' ? 'success' : 'neutral'}
                  filename={`resultado-${result.algorithm.toLowerCase().replace(/\s/g, '-')}.txt`}
                />
                {result.mode === 'encrypt' ? (
                  <div className="result-meta">
                    <span>
                      <em>Esquema</em>
                      <strong>{result.algorithm}</strong>
                    </span>
                    <span>
                      <em>Detalle</em>
                      <strong>{result.detail}</strong>
                    </span>
                    <span>
                      <em>Huella</em>
                      <strong className="mono">{fingerprint.slice(0, 16)}…</strong>
                    </span>
                  </div>
                ) : null}
              </>
            ) : null}
          </div>
        </Panel>

        <div className="side-stack">
          <Panel
            title="Claves"
            subtitle="Se generan en el navegador y viven solo en memoria."
            icon={KeyRound}
            actions={
              <Button size="sm" icon={KeyRound} onClick={generateKeys} loading={busy}>
                {activeBundle ? 'Regenerar' : 'Generar par'}
              </Button>
            }
          >
            {busy ? (
              <div className="key-loading">
                <Spinner label={`Generando clave ${current.label}…`} />
                <p>RSA puede tardar unos segundos según el tamaño.</p>
              </div>
            ) : activeBundle ? (
              <div className="key-stack">
                <div className="key-status">
                  <span className="key-status-icon">
                    <ShieldCheck size={16} />
                  </span>
                  <div>
                    <strong>Par listo · {current.label}</strong>
                    <span>
                      {privateKey ? 'Clave privada disponible' : 'Solo clave pública (importada)'}
                    </span>
                  </div>
                  <Badge tone={privateKey ? 'success' : 'warn'}>
                    {privateKey ? 'completo' : 'público'}
                  </Badge>
                </div>

                <KeyValue
                  label="Huella SHA-256"
                  value={fingerprint}
                  display={`${fingerprint.slice(0, 24)}…${fingerprint.slice(-6)}`}
                />

                {publicKey ? (
                  <KeyValue
                    label="Clave pública"
                    value={
                      typeof publicKey === 'string' ? publicKey : JSON.stringify(publicKey)
                    }
                    display={
                      alg === 'ELGAMAL' && typeof publicKey === 'string'
                        ? hexPreview(publicKey, 22, 10)
                        : alg === 'ECIES' && typeof publicKey === 'string'
                          ? `${publicKey.slice(0, 24)}…`
                          : fingerprint.slice(0, 32)
                    }
                  />
                ) : null}

                {privateKey ? (
                  <div className="private-row">
                    <span>
                      <Lock size={13} /> Clave privada en memoria
                    </span>
                    <button
                      type="button"
                      className="link-btn"
                      onClick={() => setShowPrivate((value) => !value)}
                    >
                      {showPrivate ? <EyeOff size={13} /> : <Eye size={13} />}
                      {showPrivate ? 'Ocultar' : 'Mostrar'}
                    </button>
                    {showPrivate ? (
                      <p className="private-value">
                        {typeof privateKey === 'string'
                          ? hexPreview(privateKey, 36, 16)
                          : 'JWK privada (usa Exportar para verla completa)'}
                      </p>
                    ) : null}
                  </div>
                ) : null}

                <div className="key-actions">
                  {publicBundle() ? (
                    <Button
                      variant="soft"
                      size="sm"
                      icon={Upload}
                      onClick={() =>
                        downloadText(`clave-${alg.toLowerCase()}-publica.json`, publicBundle()!)
                      }
                    >
                      Exportar pública
                    </Button>
                  ) : null}
                  {privateBundle() ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Download}
                      onClick={() =>
                        downloadText(`clave-${alg.toLowerCase()}-privada.json`, privateBundle()!)
                      }
                    >
                      Exportar par
                    </Button>
                  ) : null}
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={KeyRound}
                    onClick={() => setImportOpen((value) => !value)}
                  >
                    Importar
                  </Button>
                </div>

                {importOpen ? (
                  <div className="import-box">
                    <TextAreaField
                      label="JSON de claves"
                      value={importText}
                      onChange={(event) => setImportText(event.target.value)}
                      rows={5}
                      mono
                      placeholder='{"alg":"ECIES-P256","publicKey":"…","secretKey":"…"}'
                      hint="Acepta un par completo o solo la clave pública."
                    />
                    <div className="form-actions">
                      <Button size="sm" icon={Upload} onClick={importBundle} disabled={!importText.trim()}>
                        Cargar claves
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setImportOpen(false)
                          setImportText('')
                        }}
                      >
                        Cancelar
                      </Button>
                    </div>
                  </div>
                ) : null}

                <Alert tone="warn" title="Clave privada">
                  Exportar el par crea un archivo sin protección. Guárdalo en un lugar seguro.
                </Alert>
              </div>
            ) : (
              <EmptyState icon={KeyRound} title="Aún no hay claves">
                Genera un par {current.label} para cifrar o descifrar. También puedes importar un
                JSON exportado antes.
                <div className="empty-actions">
                  <Button size="sm" icon={KeyRound} onClick={generateKeys}>
                    Generar par
                  </Button>
                  <Button size="sm" variant="ghost" icon={KeyRound} onClick={() => setImportOpen(true)}>
                    Importar
                  </Button>
                </div>
                {importOpen ? (
                  <div className="import-box">
                    <TextAreaField
                      label="JSON de claves"
                      value={importText}
                      onChange={(event) => setImportText(event.target.value)}
                      rows={5}
                      mono
                      placeholder='{"alg":"RSA-OAEP","publicKey":{…}}'
                    />
                    <Button size="sm" icon={Upload} onClick={importBundle} disabled={!importText.trim()}>
                      Cargar claves
                    </Button>
                  </div>
                ) : null}
              </EmptyState>
            )}
          </Panel>
        </div>
      </div>

      <div className="section-footnote">
        <LockOpen size={14} />
        Las claves se borran al recargar la página. Exporta el par si necesitas conservarlo.
      </div>
    </div>
  )
}
