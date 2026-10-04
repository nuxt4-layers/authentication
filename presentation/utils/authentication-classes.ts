/**
 * Utility classes from the SemanticPresentationTheme vocabulary (Theme Manager's
 * semantic presentation grammar), shared by the layer's components. Kept as
 * literal strings so Tailwind can find them through tailwind.css. Sizes come
 * from Theme Manager's scales too, never Tailwind's defaults.
 *
 * Fill, Pen and Edge of one surface or control share a role and a state, and
 * advance together (hover, active and disabled). Text and borders without a
 * fill of their own sit on the card (fill-base-default). The only exceptions
 * are DELIBERATE_PAIRINGS below, each also listed in
 * docs/contracts.md (Styling); tests/presentation.test.ts enforces both.
 */

// The focus indicator is the surrounding card's own edge in its active state,
// so it is judged against the surface it sits on (WCAG 1.4.11).
const focus = 'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-edge-base-active'

// Links are link-role surfaces: link pen on link fill, underlined.
const linkSurface = 'rounded-sm bg-fill-link-default px-1 text-pen-link-default underline hover:bg-fill-link-hover hover:text-pen-link-hover active:bg-fill-link-active active:text-pen-link-active'

export const authenticationClasses = {
  page: 'min-h-screen bg-fill-floor-default text-pen-floor-default px-4 py-8 font-sans',
  card: 'mx-auto w-full max-w-md rounded-lg border border-edge-base-default bg-fill-base-default p-6 text-pen-base-default',
  wideCard: 'mx-auto w-full max-w-2xl rounded-lg border border-edge-base-default bg-fill-base-default p-6 text-pen-base-default',
  title: 'mb-4 text-2xl font-semibold text-pen-base-default',
  section: 'mt-8 border-t border-edge-base-default pt-6',
  sectionTitle: 'mb-3 text-xl font-semibold text-pen-base-default',
  text: 'text-base text-pen-base-default',
  muted: 'text-sm text-pen-muted-default',
  stack: 'flex flex-col gap-4',
  row: 'flex flex-wrap items-center gap-3',
  label: 'block text-sm font-medium text-pen-base-default',
  input: `mt-1 block w-full rounded-md border border-edge-input-default bg-fill-input-default px-3 py-2 text-base text-pen-input-default aria-[invalid=true]:border-edge-error-default ${focus}`,
  hint: 'mt-1 text-sm text-pen-muted-default',
  fieldError: 'mt-1 text-sm font-medium text-pen-error-default',
  primaryButton: `inline-flex min-h-8 w-full items-center justify-center rounded-md border border-edge-primary-default bg-fill-primary-default px-4 py-2 text-base font-semibold text-pen-primary-default hover:border-edge-primary-hover hover:bg-fill-primary-hover hover:text-pen-primary-hover active:border-edge-primary-active active:bg-fill-primary-active active:text-pen-primary-active disabled:border-edge-primary-disabled disabled:bg-fill-primary-disabled disabled:text-pen-primary-disabled ${focus}`,
  secondaryButton: `inline-flex min-h-8 items-center justify-center rounded-md border border-edge-secondary-default bg-fill-secondary-default px-4 py-2 text-base font-medium text-pen-secondary-default hover:border-edge-secondary-hover hover:bg-fill-secondary-hover hover:text-pen-secondary-hover active:border-edge-secondary-active active:bg-fill-secondary-active active:text-pen-secondary-active disabled:border-edge-secondary-disabled disabled:bg-fill-secondary-disabled disabled:text-pen-secondary-disabled ${focus}`,
  dangerButton: `inline-flex min-h-8 items-center justify-center rounded-md border border-edge-error-default bg-fill-error-default px-4 py-2 text-base font-medium text-pen-error-default hover:border-edge-error-hover hover:bg-fill-error-hover hover:text-pen-error-hover active:border-edge-error-active active:bg-fill-error-active active:text-pen-error-active disabled:border-edge-error-disabled disabled:bg-fill-error-disabled disabled:text-pen-error-disabled ${focus}`,
  toggleButton: `ml-2 inline-flex min-h-6 items-center text-sm ${linkSurface} ${focus}`,
  link: `${linkSurface} ${focus}`,
  // A link standing on its own line: at least 24px tall (WCAG 2.2 target size).
  actionLink: `inline-flex min-h-6 items-center ${linkSurface} ${focus}`,
  alertError: 'rounded-md border border-edge-error-default bg-fill-error-default p-4 text-pen-error-default',
  alertSuccess: 'rounded-md border border-edge-success-default bg-fill-success-default p-4 text-pen-success-default',
  alertInfo: 'rounded-md border border-edge-info-default bg-fill-info-default p-4 text-pen-info-default',
  divider: 'my-4 flex items-center gap-3 text-sm text-pen-muted-default',
  list: 'flex flex-col divide-y divide-edge-base-default',
  listItem: 'flex flex-wrap items-center justify-between gap-3 py-3',
  code: 'font-mono text-base text-pen-base-default',
} as const

/**
 * Pen or Edge tokens drawn on a fill of another role or state, each because
 * the meaning requires it. A host's theme must keep these legible.
 */
export const DELIBERATE_PAIRINGS = [
  // Secondary text (hints, notes, the "or" divider) on the card.
  { token: 'pen-muted-default', on: 'fill-base-default' },
  // A field's error message under the field, on the card.
  { token: 'pen-error-default', on: 'fill-base-default' },
  // An invalid field's border.
  { token: 'edge-error-default', on: 'fill-input-default' },
  // The focus indicator around controls on the card.
  { token: 'edge-base-active', on: 'fill-base-default' },
] as const
