import {
  useId,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react'
import {
  Check,
  ChevronDown,
  ClipboardCheck,
  Copy,
  Download,
  Info,
  LoaderCircle,
  ShieldAlert,
  TriangleAlert,
  CircleCheck,
  type LucideIcon,
} from 'lucide-react'
import { copyText, downloadText } from '../lib/bytes'

/* --------------------------------- botones -------------------------------- */

type ButtonVariant = 'primary' | 'soft' | 'ghost' | 'outline' | 'danger'
type ButtonSize = 'sm' | 'md' | 'lg'

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  icon: Icon,
  loading = false,
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: ButtonSize
  icon?: LucideIcon
  loading?: boolean
}) {
  return (
    <button
      className={`btn btn-${variant} btn-${size} ${className}`}
      {...props}
      disabled={props.disabled || loading}
    >
      {loading ? <LoaderCircle className="spin" size={16} /> : Icon ? <Icon size={16} /> : null}
      <span>{children}</span>
    </button>
  )
}

export function IconButton({
  icon: Icon,
  label,
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { icon: LucideIcon; label: string }) {
  return (
    <button className={`icon-btn ${className}`} aria-label={label} title={label} {...props}>
      <Icon size={16} />
    </button>
  )
}

export function CopyButton({
  value,
  label = 'Copiar',
  compact = false,
  className = '',
}: {
  value: string
  label?: string
  compact?: boolean
  className?: string
}) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await copyText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  if (compact) {
    return (
      <IconButton
        icon={copied ? Check : Copy}
        label={copied ? 'Copiado' : label}
        onClick={handleCopy}
        className={`${copied ? 'is-success' : ''} ${className}`}
      />
    )
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      icon={copied ? ClipboardCheck : Copy}
      onClick={handleCopy}
      className={className}
    >
      {copied ? 'Copiado' : label}
    </Button>
  )
}

/* ------------------------------- formularios ------------------------------ */

export function TextField({
  label,
  hint,
  action,
  error,
  className = '',
  ...props
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string
  hint?: ReactNode
  action?: ReactNode
  error?: string
}) {
  const id = useId()
  return (
    <div className={`field ${className}`}>
      <div className="field-head">
        <label htmlFor={id}>{label}</label>
        {action}
      </div>
      <input id={id} className={`input ${error ? 'has-error' : ''}`} {...props} />
      {hint && !error ? <p className="field-hint">{hint}</p> : null}
      {error ? <p className="field-error">{error}</p> : null}
    </div>
  )
}

export function TextAreaField({
  label,
  hint,
  error,
  rows = 6,
  action,
  mono = false,
  className = '',
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement> & {
  label: string
  hint?: ReactNode
  action?: ReactNode
  error?: string
  mono?: boolean
}) {
  const id = useId()
  return (
    <div className={`field ${className}`}>
      <div className="field-head">
        <label htmlFor={id}>{label}</label>
        {action}
      </div>
      <textarea
        id={id}
        rows={rows}
        className={`input textarea ${mono ? 'mono' : ''} ${error ? 'has-error' : ''}`}
        {...props}
      />
      {hint && !error ? <p className="field-hint">{hint}</p> : null}
      {error ? <p className="field-error">{error}</p> : null}
    </div>
  )
}

export function SelectField({
  label,
  hint,
  children,
  className = '',
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & {
  label: string
  hint?: ReactNode
}) {
  const id = useId()
  return (
    <div className={`field ${className}`}>
      <label htmlFor={id}>{label}</label>
      <div className="select-wrap">
        <select id={id} className="input select" {...props}>
          {children}
        </select>
        <ChevronDown size={15} aria-hidden="true" />
      </div>
      {hint ? <p className="field-hint">{hint}</p> : null}
    </div>
  )
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
  className = '',
}: {
  value: T
  options: { value: T; label: string; icon?: LucideIcon }[]
  onChange: (value: T) => void
  label?: string
  className?: string
}) {
  return (
    <div className={`segmented ${className}`} role="tablist" aria-label={label}>
      {options.map((option) => {
        const Icon = option.icon
        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={value === option.value}
            className={`segmented-item ${value === option.value ? 'is-active' : ''}`}
            onClick={() => onChange(option.value)}
          >
            {Icon ? <Icon size={14} /> : null}
            {option.label}
          </button>
        )
      })}
    </div>
  )
}

/* -------------------------------- estructura ------------------------------ */

export function Panel({
  title,
  subtitle,
  icon: Icon,
  actions,
  children,
  className = '',
}: {
  title?: ReactNode
  subtitle?: ReactNode
  icon?: LucideIcon
  actions?: ReactNode
  children: ReactNode
  className?: string
  glow?: string
}) {
  return (
    <div className={`panel ${className}`}>
      {title ? (
        <div className="panel-head">
          <div className="panel-title-wrap">
            {Icon ? (
              <span className="panel-icon">
                <Icon size={16} />
              </span>
            ) : null}
            <div>
              <h3 className="panel-title">{title}</h3>
              {subtitle ? <p className="panel-subtitle">{subtitle}</p> : null}
            </div>
          </div>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </div>
  )
}

export function SectionHeader({
  eyebrow,
  title,
  lead,
  actions,
}: {
  eyebrow?: string
  title: ReactNode
  lead?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="section-header">
      <div>
        {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
        <h1>{title}</h1>
        {lead ? <p className="lead">{lead}</p> : null}
      </div>
      {actions ? <div className="section-header-actions">{actions}</div> : null}
    </header>
  )
}

export function Badge({
  children,
  tone = 'neutral',
  dot = false,
}: {
  children: ReactNode
  tone?: 'neutral' | 'brand' | 'success' | 'warn' | 'danger' | 'info'
  dot?: boolean
}) {
  return (
    <span className={`badge badge-${tone}`}>
      {dot ? <span className="badge-dot" /> : null}
      {children}
    </span>
  )
}

export function Alert({
  children,
  tone = 'info',
  title,
}: {
  children: ReactNode
  tone?: 'info' | 'warn' | 'danger' | 'success'
  title?: string
}) {
  const Icon =
    tone === 'danger' || tone === 'warn'
      ? TriangleAlert
      : tone === 'success'
        ? CircleCheck
        : tone === 'info'
          ? Info
          : ShieldAlert
  return (
    <div className={`alert alert-${tone}`} role={tone === 'danger' ? 'alert' : undefined}>
      <Icon size={16} className="alert-icon" />
      <div>
        {title ? <strong>{title}</strong> : null}
        {children}
      </div>
    </div>
  )
}

export function OutputBox({
  value,
  label = 'Resultado',
  placeholder = 'El resultado aparecerá aquí.',
  filename = 'resultado.txt',
  rows = 6,
  tone = 'neutral',
}: {
  value: string
  label?: string
  placeholder?: string
  filename?: string
  rows?: number
  tone?: 'neutral' | 'success' | 'danger'
}) {
  return (
    <div className={`output output-${tone}`}>
      <div className="output-head">
        <span>{label}</span>
        <div className="output-actions">
          <span className="output-count">{value ? `${value.length} caracteres` : 'vacío'}</span>
          {value ? (
            <>
              <CopyButton value={value} compact />
              <IconButton
                icon={Download}
                label="Descargar resultado"
                onClick={() => downloadText(filename, value)}
              />
            </>
          ) : null}
        </div>
      </div>
      {value ? (
        <pre className="output-body" style={{ maxHeight: `${Math.max(110, rows * 20)}px` }}>
          {value}
        </pre>
      ) : (
        <p className="output-empty">{placeholder}</p>
      )}
    </div>
  )
}

export function KeyValue({
  label,
  value,
  copy = true,
  mono = true,
  display,
}: {
  label: string
  value: string
  copy?: boolean
  mono?: boolean
  display?: string
}) {
  return (
    <div className="kv">
      <span className="kv-label">{label}</span>
      <span className={`kv-value ${mono ? 'mono' : ''}`} title={value}>
        {display ?? value}
      </span>
      {copy ? <CopyButton value={value} compact /> : null}
    </div>
  )
}

export function Stat({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: LucideIcon
  label: string
  value: ReactNode
  hint?: string
}) {
  return (
    <div className="stat">
      <span className="stat-icon">
        <Icon size={16} />
      </span>
      <div>
        <span className="stat-value">{value}</span>
        <span className="stat-label">{label}</span>
        {hint ? <span className="stat-hint">{hint}</span> : null}
      </div>
    </div>
  )
}

export function AlgorithmCard({
  name,
  meta,
  selected,
  onClick,
  tone = 'neutral',
  trailing,
}: {
  name: string
  meta?: string
  selected: boolean
  onClick: () => void
  tone?: 'neutral' | 'warn' | 'danger'
  trailing?: ReactNode
}) {
  return (
    <button
      type="button"
      className={`algo-card ${selected ? 'is-selected' : ''} algo-${tone}`}
      onClick={onClick}
      aria-pressed={selected}
    >
      <span className="algo-name">{name}</span>
      {meta ? <span className="algo-meta">{meta}</span> : null}
      {trailing}
    </button>
  )
}

export function Spinner({ label = 'Procesando…' }: { label?: string }) {
  return (
    <span className="spinner-line">
      <LoaderCircle size={15} className="spin" />
      {label}
    </span>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon
  title: string
  children?: ReactNode
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon size={20} />
      </span>
      <strong>{title}</strong>
      {children ? <div className="empty-body">{children}</div> : null}
    </div>
  )
}
