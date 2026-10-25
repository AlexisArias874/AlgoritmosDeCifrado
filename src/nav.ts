import { KeyRound, LockKeyhole, ScrollText, type LucideIcon } from 'lucide-react'

export type SectionId = 'simetrico' | 'asimetrico' | 'clasicos'

export type VisibleSectionId = SectionId

export type SectionDef = {
  id: SectionId
  label: string
  short: string
  description: string
  icon: LucideIcon
}

export const SECTIONS: SectionDef[] = [
  {
    id: 'simetrico',
    label: 'Simétrico',
    short: 'Simétrico',
    description: 'Una sola clave para cifrar y descifrar',
    icon: LockKeyhole,
  },
  {
    id: 'asimetrico',
    label: 'Asimétrico',
    short: 'Asimétrico',
    description: 'Par de claves pública y privada',
    icon: KeyRound,
  },
  {
    id: 'clasicos',
    label: 'Clásicos',
    short: 'Clásicos',
    description: 'Métodos históricos de cifrado',
    icon: ScrollText,
  },
]

export const sectionById = (id: SectionId): SectionDef =>
  SECTIONS.find((section) => section.id === id) ?? SECTIONS[0]
