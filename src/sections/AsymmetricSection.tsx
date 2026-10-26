import { useState } from 'react'
import {
  BadgeCheck,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LockOpen,
  PenLine,
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
  publicBundle,
  rsaDecrypt,
  rsaEncrypt,
  rsaFingerprint,
  safeJsonParse,
  type EcKeyBundle,
  type ElGamalKeyBundle,
  type RsaKeyBundle,
} from '../lib/asymmetric'
import {
  dhDecrypt,
  dhEncrypt,
  dhFingerprint,
  generateDhKeyPair,
  hexPreview,
  type DhKeyBundle,
} from '../lib/dh'
import {
  importDhKeyMaterial,
  importEcKeyMaterial,
  importElGamalKeyMaterial,
  importMlKemKeyMaterial,
  importRsaKeyMaterial,
} from '../lib/external-keys'
import {
  generateMlKemKeyPair,
  mlKemDecrypt,
  mlKemEncrypt,
  mlKemFingerprint,
  type MlKemKeyBundle,
} from '../lib/mlkem'
import {
  generateSigKey,
  sigFingerprint,
  signMessage,
  verifyMessage,
  SIGNATURE_ALGORITHMS,
  type SigAlg,
  type SigBundle,
} from '../lib/signatures'

type Alg = 'RSA' | 'ECC' | 'DH' | 'DSA' | 'ECDSA' | 'EdDSA' | 'ELGAMAL' | 'ML-KEM' | 'ML-DSA'
type Mode = 'encrypt' | 'decrypt'
type SigMode = 'sign' | 'verify'
type RsaMode = 'hybrid' | 'direct'

type EncResult = {
  value: string
  label: string
  algorithm: string
  detail: string
  mode: Mode
}

type SigResult =
  | {
      mode: 'sign'
      value: string
      algorithm: string
      fingerprint: string
    }
  | {
      mode: 'verify'
      valid: boolean
      algorithm: string
      fingerprint: string
    }

const ALGORITHMS: {
  id: Alg
  name: string
  meta: string
  kind: 'encrypt' | 'sign'
}[] = [
  { id: 'RSA', name: 'RSA', meta: 'OAEP · 2048/3072/4096', kind: 'encrypt' },
  { id: 'ECC', name: 'ECC', meta: 'ECIES P-256 · cifrado', kind: 'encrypt' },
  { id: 'DH', name: 'Diffie-Hellman', meta: 'MODP 2048 · acuerdo de claves', kind: 'encrypt' },
  { id: 'DSA', name: 'DSA', meta: 'Firma · 2048/256', kind: 'sign' },
  { id: 'ECDSA', name: 'ECDSA', meta: 'Firma · curva P-256', kind: 'sign' },
  { id: 'EdDSA', name: 'EdDSA', meta: 'Firma · Ed25519', kind: 'sign' },
  { id: 'ELGAMAL', name: 'ElGamal', meta: 'MODP 2048 · cifrado híbrido', kind: 'encrypt' },
  { id: 'ML-KEM', name: 'ML-KEM', meta: 'Kyber · FIPS 203', kind: 'encrypt' },
  { id: 'ML-DSA', name: 'ML-DSA', meta: 'Dilithium · FIPS 204', kind: 'sign' },
]

const SIG_MAP: Partial<Record<Alg, SigAlg>> = {
  DSA: 'DSA-2048',
  ECDSA: 'ECDSA-P256',
  EdDSA: 'Ed25519',
  'ML-DSA': 'ML-DSA-65',
}

const UI_BY_SIG: Partial<Record<string, Alg>> = {
  'DSA-2048': 'DSA',
  'ECDSA-P256': 'ECDSA',
  Ed25519: 'EdDSA',
  'ML-DSA-65': 'ML-DSA',
}

const IMPORT_HELP: Record<Alg, { label: string; placeholder: string; hint: string }> = {
  RSA: {
    label: 'Clave RSA',
    placeholder: '-----BEGIN PRIVATE KEY-----',
    hint: 'Acepta un JSON exportado, un JWK RSA o un PEM PKCS#8/SPKI. Con la clave privada puedes descifrar paquetes externos.',
  },
  ECC: {
    label: 'Clave ECC P-256',
    placeholder: '-----BEGIN PRIVATE KEY-----',
    hint: 'Acepta un JSON exportado, JWK, PEM P-256 o una clave en base64/hex. Solo la privada ya permite descifrar.',
  },
  DH: {
    label: 'Clave privada Diffie-Hellman',
    placeholder: 'a1b2c3… (64 caracteres hex)',
    hint: 'Pega la clave privada en hexadecimal. La clave pública se deriva automáticamente.',
  },
  DSA: {
    label: 'Par de firma DSA',
    placeholder: '{"alg":"DSA-2048","publicKey":"…","privateKey":"…"}',
    hint: 'Acepta un par exportado por esta aplicación.',
  },
  ECDSA: {
    label: 'Par de firma ECDSA',
    placeholder: '{"alg":"ECDSA-P256","publicKey":"…","privateKey":"…"}',
    hint: 'Acepta un par exportado por esta aplicación.',
  },
  EdDSA: {
    label: 'Par de firma EdDSA',
    placeholder: '{"alg":"Ed25519","publicKey":"…","privateKey":"…"}',
    hint: 'Acepta un par exportado por esta aplicación.',
  },
  ELGAMAL: {
    label: 'Clave privada ElGamal',
    placeholder: 'a1b2c3… (64 caracteres hex)',
    hint: 'Pega la clave privada en hexadecimal. La clave pública se deriva automáticamente.',
  },
  'ML-KEM': {
    label: 'Clave ML-KEM-768',
    placeholder: 'Base64 o hexadecimal de 2400 bytes',
    hint: 'Acepta un JSON exportado o la clave privada en base64/hex. La clave pública se deriva automáticamente.',
  },
  'ML-DSA': {
    label: 'Par de firma ML-DSA',
    placeholder: '{"alg":"ML-DSA-65","publicKey":"…","privateKey":"…"}',
    hint: 'Acepta un par exportado por esta aplicación.',
  },
}

export default function AsymmetricSection() {
  const [alg, setAlg] = useState<Alg>('RSA')
  const [mode, setMode] = useState<Mode>('encrypt')
  const [sigMode, setSigMode] = useState<SigMode>('sign')
  const [rsa, setRsa] = useState<RsaKeyBundle | null>(null)
  const [ec, setEc] = useState<EcKeyBundle | null>(null)
  const [elgamal, setElgamal] = useState<ElGamalKeyBundle | null>(null)
  const [mlkem, setMlkem] = useState<MlKemKeyBundle | null>(null)
  const [dh, setDh] = useState<DhKeyBundle | null>(null)
  const [sigKeys, setSigKeys] = useState<Partial<Record<SigAlg, SigBundle>>>({})
  const [rsaBits, setRsaBits] = useState(2048)
  const [rsaMode, setRsaMode] = useState<RsaMode>('hybrid')
  const [plaintext, setPlaintext] = useState('')
  const [payload, setPayload] = useState('')
  const [result, setResult] = useState<EncResult | null>(null)
  const [sigMessage, setSigMessage] = useState('')
  const [sigPackage, setSigPackage] = useState('')
  const [sigResult, setSigResult] = useState<SigResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [showPrivate, setShowPrivate] = useState(false)

  const current = ALGORITHMS.find((item) => item.id === alg)!
  const sigAlg = SIG_MAP[alg] ?? null
  const isSignature = sigAlg !== null
  const signatureBundle = sigAlg ? sigKeys[sigAlg] : undefined
  const importHelp = IMPORT_HELP[alg]

  const currentBundle: object | null = isSignature
    ? (signatureBundle ?? null)
    : alg === 'RSA'
      ? rsa
      : alg === 'ECC'
        ? ec
        : alg === 'ELGAMAL'
          ? elgamal
          : alg === 'ML-KEM'
            ? mlkem
            : alg === 'DH'
              ? dh
              : null

  const publicKeyText = isSignature
    ? (signatureBundle?.publicKey ?? '')
    : alg === 'RSA'
      ? rsa
        ? JSON.stringify(rsa.publicKey)
        : ''
      : alg === 'ECC'
        ? (ec?.publicKey ?? '')
        : alg === 'ELGAMAL'
          ? (elgamal?.publicKey ?? '')
          : alg === 'ML-KEM'
            ? (mlkem?.publicKey ?? '')
            : (dh?.publicKey ?? '')

  const privateKeyText = isSignature
    ? (signatureBundle?.privateKey ?? '')
    : alg === 'RSA'
      ? rsa?.privateKey
        ? JSON.stringify(rsa.privateKey)
        : ''
      : alg === 'ECC'
        ? (ec?.secretKey ?? '')
        : alg === 'ELGAMAL'
          ? (elgamal?.secretKey ?? '')
          : alg === 'ML-KEM'
            ? (mlkem?.secretKey ?? '')
            : (dh?.secretKey ?? '')
  const hasPrivateKey = Boolean(privateKeyText)

  const fingerprint = signatureBundle
    ? sigFingerprint(signatureBundle)
    : alg === 'RSA' && rsa
      ? rsaFingerprint(rsa)
      : alg === 'ECC' && ec
        ? ecFingerprint(ec)
        : alg === 'ELGAMAL' && elgamal
          ? elgamalFingerprint(elgamal)
          : alg === 'ML-KEM' && mlkem
            ? mlKemFingerprint(mlkem)
            : alg === 'DH' && dh
              ? dhFingerprint(dh)
              : ''

  const publicExport = currentBundle
    ? JSON.stringify(publicBundle(currentBundle), null, 2)
    : null
  const privateExport = currentBundle ? JSON.stringify(currentBundle, null, 2) : null

  const generateKeys = async () => {
    setBusy(true)
    setError('')
    try {
      if (sigAlg) {
        const bundle = await generateSigKey(sigAlg)
        setSigKeys((previous) => ({ ...previous, [sigAlg]: bundle }))
      } else if (alg === 'RSA') {
        setRsa(await generateRsaKeyPair(rsaBits))
      } else if (alg === 'ECC') {
        setEc(generateEcKeyPair())
      } else if (alg === 'ELGAMAL') {
        setElgamal(generateElGamalKeyPair())
      } else if (alg === 'ML-KEM') {
        setMlkem(generateMlKemKeyPair())
      } else {
        setDh(generateDhKeyPair())
      }
      setResult(null)
      setSigResult(null)
      setShowPrivate(false)
    } catch (caught) {
      setError(formatError(caught))
    } finally {
      setBusy(false)
    }
  }

  const importBundle = async () => {
    setError('')
    setImporting(true)
    try {
      const text = importText.trim()
      if (!text) throw new Error('Pega una clave o un par de claves para continuar.')

      if (isSignature) {
        const data = safeJsonParse<Record<string, unknown>>(text, 'la clave')
        if (
          typeof data.alg !== 'string' ||
          !SIGNATURE_ALGORITHMS.some((item) => item.id === data.alg) ||
          typeof data.publicKey !== 'string' ||
          !UI_BY_SIG[data.alg]
        ) {
          throw new Error('Para firmas, importa un par exportado por esta aplicación.')
        }
        const importedAlg = data.alg as SigAlg
        const targetAlg = UI_BY_SIG[importedAlg]
        if (!targetAlg) throw new Error('Algoritmo de firma no disponible en esta sección.')
        setSigKeys((previous) => ({
          ...previous,
          [importedAlg]: {
            alg: importedAlg,
            publicKey: String(data.publicKey),
            privateKey: typeof data.privateKey === 'string' ? data.privateKey : '',
            createdAt: Number(data.createdAt ?? Date.now()),
          },
        }))
        setAlg(targetAlg)
      } else if (alg === 'RSA') {
        setRsa(await importRsaKeyMaterial(text))
      } else if (alg === 'ECC') {
        setEc(await importEcKeyMaterial(text))
      } else if (alg === 'ELGAMAL') {
        setElgamal(importElGamalKeyMaterial(text))
      } else if (alg === 'ML-KEM') {
        setMlkem(importMlKemKeyMaterial(text))
      } else {
        setDh(importDhKeyMaterial(text))
      }

      setImportOpen(false)
      setImportText('')
      setResult(null)
      setSigResult(null)
      setShowPrivate(false)
    } catch (caught) {
      setError(formatError(caught))
    } finally {
      setImporting(false)
    }
  }

  const runEncryption = async () => {
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
      } else if (alg === 'ECC') {
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
      } else if (alg === 'ELGAMAL') {
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
      } else if (alg === 'ML-KEM') {
        if (!mlkem) throw new Error('Genera o importa un par de claves ML-KEM primero.')
        if (mode === 'encrypt') {
          if (!mlkem.publicKey) throw new Error('La clave importada no incluye clave pública.')
          value = mlKemEncrypt(plaintext, mlkem.publicKey)
          label = 'Paquete ML-KEM'
          detail = 'ML-KEM-768 + HKDF + AES-256-GCM'
        } else {
          if (!mlkem.secretKey) throw new Error('Necesitas la clave privada ML-KEM para descifrar.')
          value = mlKemDecrypt(payload, mlkem.secretKey)
          label = 'Texto descifrado'
          detail = 'ML-KEM-768'
        }
      } else {
        if (!dh) throw new Error('Genera o importa un par de claves Diffie-Hellman primero.')
        if (mode === 'encrypt') {
          if (!dh.publicKey) throw new Error('La clave importada no incluye clave pública.')
          value = dhEncrypt(plaintext, dh.publicKey)
          label = 'Paquete Diffie-Hellman'
          detail = 'DH MODP-2048 + HKDF + AES-256-GCM'
        } else {
          if (!dh.secretKey) throw new Error('Necesitas la clave privada DH para descifrar.')
          value = dhDecrypt(payload, dh.secretKey)
          label = 'Texto descifrado'
          detail = 'Diffie-Hellman MODP-2048'
        }
      }
      setResult({ value, label, algorithm: current.name, detail, mode })
      if (mode === 'encrypt') setPayload(value)
    } catch (caught) {
      setError(formatError(caught))
    }
  }

  const runSignature = async () => {
    setError('')
    setSigResult(null)
    try {
      if (!signatureBundle) throw new Error(`Genera o importa un par de claves ${current.name} primero.`)
      if (sigMode === 'sign') {
        if (!signatureBundle.privateKey) throw new Error('La clave importada no incluye la clave privada.')
        const value = await signMessage(sigMessage, signatureBundle)
        setSigPackage(value)
        setSigResult({
          mode: 'sign',
          value,
          algorithm: current.name,
          fingerprint: sigFingerprint(signatureBundle),
        })
      } else {
        if (!sigPackage.trim()) throw new Error('Pega la firma que quieres verificar.')
        const verified = await verifyMessage(sigMessage, sigPackage)
        setSigResult({
          mode: 'verify',
          valid: verified.valid,
          algorithm:
            SIGNATURE_ALGORITHMS.find((item) => item.id === verified.alg)?.name ?? verified.alg,
          fingerprint: verified.fingerprint,
        })
      }
    } catch (caught) {
      setError(formatError(caught))
    }
  }

  const handleAlg = (next: Alg) => {
    setAlg(next)
    setError('')
    setResult(null)
    setSigResult(null)
    setMode('encrypt')
    setSigMode('sign')
  }

  return (
    <div className="section">
      <SectionHeader
        title="Cifrado asimétrico"
        lead="Cifrado con clave pública, acuerdo de claves y firmas digitales."
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
        {isSignature ? (
          <Panel
            title={sigMode === 'sign' ? 'Firmar mensaje' : 'Verificar firma'}
            subtitle={`${current.name} · ${sigMode === 'sign' ? 'firma digital' : 'comprobación de integridad'}`}
            icon={sigMode === 'sign' ? PenLine : BadgeCheck}
            actions={
              <Segmented
                label="Acción"
                value={sigMode}
                onChange={(next) => {
                  setSigMode(next)
                  setError('')
                }}
                options={[
                  { value: 'sign', label: 'Firmar', icon: PenLine },
                  { value: 'verify', label: 'Verificar', icon: BadgeCheck },
                ]}
              />
            }
          >
            <div className="form-stack">
              <TextAreaField
                label="Mensaje"
                value={sigMessage}
                onChange={(event) => setSigMessage(event.target.value)}
                placeholder="Escribe el mensaje que quieres firmar o verificar"
                rows={7}
                hint={`${sigMessage.length} caracteres`}
              />

              {sigMode === 'verify' ? (
                <TextAreaField
                  label="Firma"
                  value={sigPackage}
                  onChange={(event) => setSigPackage(event.target.value)}
                  placeholder="CIFRA1.eyJ2Ijox…"
                  rows={7}
                  mono
                  hint="La firma incluye la clave pública necesaria para verificarla."
                />
              ) : null}

              {error ? (
                <Alert tone="danger" title="No se pudo completar">
                  {error}
                </Alert>
              ) : null}

              <div className="form-actions">
                <Button
                  icon={sigMode === 'sign' ? PenLine : BadgeCheck}
                  size="lg"
                  onClick={runSignature}
                  disabled={
                    sigMode === 'sign'
                      ? !signatureBundle?.privateKey || !sigMessage
                      : !sigMessage || !sigPackage
                  }
                >
                  {sigMode === 'sign' ? `Firmar con ${current.name}` : 'Verificar firma'}
                </Button>
                {!signatureBundle ? (
                  <span className="inline-hint">
                    <TriangleAlert size={14} /> Genera un par de claves para firmar.
                  </span>
                ) : !signatureBundle.privateKey && sigMode === 'sign' ? (
                  <span className="inline-hint">
                    <TriangleAlert size={14} /> La clave importada es solo pública.
                  </span>
                ) : null}
              </div>

              {sigResult?.mode === 'sign' ? (
                <>
                  <OutputBox
                    value={sigResult.value}
                    label="Firma digital"
                    rows={8}
                    filename={`firma-${sigResult.algorithm.toLowerCase().replace(/\s/g, '-')}.txt`}
                  />
                  <div className="result-meta">
                    <span>
                      <em>Esquema</em>
                      <strong>{sigResult.algorithm}</strong>
                    </span>
                    <span>
                      <em>Huella</em>
                      <strong className="mono">{sigResult.fingerprint.slice(0, 16)}…</strong>
                    </span>
                  </div>
                  <div className="form-actions">
                    <Button variant="ghost" size="sm" icon={BadgeCheck} onClick={() => setSigMode('verify')}>
                      Probar a verificar
                    </Button>
                  </div>
                </>
              ) : null}

              {sigResult?.mode === 'verify' ? (
                <>
                  <Alert
                    tone={sigResult.valid ? 'success' : 'danger'}
                    title={sigResult.valid ? 'Firma válida' : 'Firma inválida'}
                  >
                    {sigResult.valid
                      ? 'El mensaje no fue alterado y corresponde a la clave pública incluida en la firma.'
                      : 'El mensaje cambió, la firma está corrupta o no corresponde a esta clave.'}
                  </Alert>
                  <div className="result-meta">
                    <span>
                      <em>Esquema</em>
                      <strong>{sigResult.algorithm}</strong>
                    </span>
                    <span>
                      <em>Huella</em>
                      <strong className="mono">{sigResult.fingerprint.slice(0, 16)}…</strong>
                    </span>
                  </div>
                </>
              ) : null}
            </div>
          </Panel>
        ) : (
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
                  onClick={runEncryption}
                  disabled={
                    !currentBundle ||
                    (mode === 'encrypt' ? !plaintext : !payload || !hasPrivateKey)
                  }
                >
                  {mode === 'encrypt' ? `Cifrar con ${current.name}` : 'Descifrar paquete'}
                </Button>
                {!currentBundle ? (
                  <span className="inline-hint">
                    <TriangleAlert size={14} /> Sin claves.{' '}
                    <button
                      type="button"
                      className="link-btn"
                      onClick={() => setImportOpen(true)}
                    >
                      Usar una clave existente
                    </button>
                  </span>
                ) : mode === 'decrypt' && !hasPrivateKey ? (
                  <span className="inline-hint">
                    <TriangleAlert size={14} /> Carga la clave privada para descifrar.
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
        )}

        <div className="side-stack">
          <Panel
            title={isSignature ? 'Claves de firma' : 'Claves'}
            subtitle="Genera un par o usa una clave existente. Todo vive solo en memoria."
            icon={KeyRound}
            actions={
              <Button size="sm" icon={KeyRound} onClick={generateKeys} loading={busy}>
                {currentBundle ? 'Regenerar' : 'Generar par'}
              </Button>
            }
          >
            {busy ? (
              <div className="key-loading">
                <Spinner label={`Generando clave ${current.name}…`} />
                <p>
                  {alg === 'RSA'
                    ? 'RSA puede tardar unos segundos según el tamaño.'
                    : 'La generación puede tardar un instante.'}
                </p>
              </div>
            ) : currentBundle ? (
              <div className="key-stack">
                <div className="key-status">
                  <span className="key-status-icon">
                    <ShieldCheck size={16} />
                  </span>
                  <div>
                    <strong>Par listo · {current.name}</strong>
                    <span>
                      {privateKeyText ? 'Clave privada disponible' : 'Solo clave pública (importada)'}
                    </span>
                  </div>
                  <Badge tone={privateKeyText ? 'success' : 'warn'}>
                    {privateKeyText ? 'completo' : 'público'}
                  </Badge>
                </div>

                <KeyValue
                  label="Huella SHA-256"
                  value={fingerprint}
                  display={`${fingerprint.slice(0, 24)}…${fingerprint.slice(-6)}`}
                />

                {publicKeyText ? (
                  <KeyValue
                    label="Clave pública"
                    value={publicKeyText}
                    display={
                      alg === 'RSA'
                        ? fingerprint.slice(0, 32)
                        : alg === 'ELGAMAL' || alg === 'DH' || alg === 'DSA'
                          ? hexPreview(publicKeyText, 22, 10)
                          : `${publicKeyText.slice(0, 24)}…`
                    }
                  />
                ) : null}

                {privateKeyText ? (
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
                        {alg === 'RSA'
                          ? 'JWK privada (usa Exportar para verla completa)'
                          : alg === 'ELGAMAL' || alg === 'DH' || alg === 'DSA'
                            ? hexPreview(privateKeyText, 36, 16)
                            : `${privateKeyText.slice(0, 36)}…`}
                      </p>
                    ) : null}
                  </div>
                ) : null}

                <div className="key-actions">
                  {publicExport ? (
                    <Button
                      variant="soft"
                      size="sm"
                      icon={Upload}
                      onClick={() =>
                        downloadText(`clave-${alg.toLowerCase()}-publica.json`, publicExport)
                      }
                    >
                      Exportar pública
                    </Button>
                  ) : null}
                  {privateExport ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Download}
                      onClick={() =>
                        downloadText(`clave-${alg.toLowerCase()}-privada.json`, privateExport)
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
                    Usar clave
                  </Button>
                </div>

                {importOpen ? (
                  <div className="import-box">
                    <TextAreaField
                      label={importHelp.label}
                      value={importText}
                      onChange={(event) => setImportText(event.target.value)}
                      rows={5}
                      mono
                      placeholder={importHelp.placeholder}
                      hint={importHelp.hint}
                    />
                    <div className="form-actions">
                      <Button
                        size="sm"
                        icon={Upload}
                        onClick={importBundle}
                        loading={importing}
                        disabled={!importText.trim()}
                      >
                        Usar clave
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
                Genera un par {current.name} para {isSignature ? 'firmar o verificar' : 'cifrar o descifrar'}.
                También puedes usar una clave privada existente o importar un par exportado.
                <div className="empty-actions">
                  <Button size="sm" icon={KeyRound} onClick={generateKeys}>
                    Generar par
                  </Button>
                  <Button size="sm" variant="ghost" icon={KeyRound} onClick={() => setImportOpen(true)}>
                    Usar clave
                  </Button>
                </div>
                {importOpen ? (
                  <div className="import-box">
                    <TextAreaField
                      label={importHelp.label}
                      value={importText}
                      onChange={(event) => setImportText(event.target.value)}
                      rows={5}
                      mono
                      placeholder={importHelp.placeholder}
                      hint={importHelp.hint}
                    />
                    <Button
                      size="sm"
                      icon={Upload}
                      onClick={importBundle}
                      loading={importing}
                      disabled={!importText.trim()}
                    >
                      Usar clave
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
