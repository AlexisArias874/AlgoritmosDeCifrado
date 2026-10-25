import { useEffect, useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { SECTIONS, sectionById, type VisibleSectionId } from './nav'
import { useTheme } from './hooks/useTheme'
import SymmetricSection from './sections/SymmetricSection'
import AsymmetricSection from './sections/AsymmetricSection'
import ClassicSection from './sections/ClassicSection'

const SECTION_COMPONENTS: Record<VisibleSectionId, () => React.ReactNode> = {
  simetrico: SymmetricSection,
  asimetrico: AsymmetricSection,
  clasicos: ClassicSection,
}

const readInitialSection = (): VisibleSectionId => {
  const hash = window.location.hash.replace('#', '')
  return SECTIONS.some((section) => section.id === hash)
    ? (hash as VisibleSectionId)
    : 'simetrico'
}

export default function App() {
  const [active, setActive] = useState<VisibleSectionId>(readInitialSection)
  const [theme, toggleTheme] = useTheme()
  const current = sectionById(active)

  const navigate = (id: VisibleSectionId) => {
    setActive(id)
    history.replaceState(null, '', `#${id}`)
    window.scrollTo({ top: 0, behavior: 'auto' })
  }

  useEffect(() => {
    const onHash = () => setActive(readInitialSection())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    document.title = `${current.label} · Cifrado de textos`
  }, [current.label])

  return (
    <>
      <a className="skip-link" href="#contenido">
        Saltar al contenido
      </a>

      <header className="topbar">
        <div className="topbar-inner">
          <span className="page-title">Cifrado de textos</span>

          <nav className="tabs" aria-label="Secciones">
            {SECTIONS.map((section) => (
              <button
                key={section.id}
                type="button"
                className={`tab ${active === section.id ? 'is-active' : ''}`}
                onClick={() => navigate(section.id as VisibleSectionId)}
                aria-current={active === section.id ? 'page' : undefined}
              >
                {section.label}
              </button>
            ))}
          </nav>

          <button
            type="button"
            className="theme-button"
            onClick={toggleTheme}
            aria-label={theme === 'light' ? 'Activar tema oscuro' : 'Activar tema claro'}
            title={theme === 'light' ? 'Activar tema oscuro' : 'Activar tema claro'}
          >
            {theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}
          </button>
        </div>
      </header>

      <main className="main" id="contenido">
        <div className="content">
          {SECTIONS.map((section) => {
            const Component = SECTION_COMPONENTS[section.id as VisibleSectionId]
            const isActive = active === section.id
            return (
              <section
                key={section.id}
                id={section.id}
                className="section-pane"
                hidden={!isActive}
                aria-label={section.label}
              >
                <Component />
              </section>
            )
          })}
        </div>
      </main>

      <span className="sr-only" aria-live="polite">
        Sección activa: {current.label}
      </span>
    </>
  )
}
