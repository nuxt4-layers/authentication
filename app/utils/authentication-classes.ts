/**
 * Utility classes from the SemanticPresentationTheme vocabulary (Theme Manager's
 * tailwind-config.css), shared by the layer's components. Every utility resolves
 * to a Theme Manager token (colour roles and states, its text, weight, radius
 * and spacing scales); none falls back to Tailwind's defaults.
 *
 * Composition follows Theme Manager's semantic presentation guide: a control's
 * edge, fill and pen share one role and advance together through its states
 * (default, hover, active, disabled). Deliberate cross-role uses, by meaning:
 * - pen-muted (hints, dividers), pen-link (links) and pen-error (a field's
 *   error message) are text on the card's base surface;
 * - an invalid input takes edge-error on its input surface;
 * - the keyboard focus indicator is edge-accent on whatever surface it rings.
 */
const focus = 'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-edge-accent-default'

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
  primaryButton: `inline-flex min-h-8 w-full items-center justify-center rounded-md border px-4 py-2 text-base font-semibold border-edge-primary-default bg-fill-primary-default text-pen-primary-default hover:border-edge-primary-hover hover:bg-fill-primary-hover hover:text-pen-primary-hover active:border-edge-primary-active active:bg-fill-primary-active active:text-pen-primary-active disabled:border-edge-primary-disabled disabled:bg-fill-primary-disabled disabled:text-pen-primary-disabled ${focus}`,
  secondaryButton: `inline-flex min-h-8 items-center justify-center rounded-md border px-4 py-2 text-base font-medium border-edge-secondary-default bg-fill-secondary-default text-pen-secondary-default hover:border-edge-secondary-hover hover:bg-fill-secondary-hover hover:text-pen-secondary-hover active:border-edge-secondary-active active:bg-fill-secondary-active active:text-pen-secondary-active disabled:border-edge-secondary-disabled disabled:bg-fill-secondary-disabled disabled:text-pen-secondary-disabled ${focus}`,
  dangerButton: `inline-flex min-h-8 items-center justify-center rounded-md border px-4 py-2 text-base font-medium border-edge-error-default bg-fill-error-default text-pen-error-default hover:border-edge-error-hover hover:bg-fill-error-hover hover:text-pen-error-hover active:border-edge-error-active active:bg-fill-error-active active:text-pen-error-active disabled:border-edge-error-disabled disabled:bg-fill-error-disabled disabled:text-pen-error-disabled ${focus}`,
  toggleButton: `ml-2 inline-flex min-h-6 items-center rounded-sm px-2 text-sm text-pen-link-default underline hover:text-pen-link-hover ${focus}`,
  link: `text-pen-link-default underline hover:text-pen-link-hover ${focus}`,
  // A link standing on its own line: at least 24px tall (WCAG 2.2 target size).
  actionLink: `inline-flex min-h-6 items-center text-pen-link-default underline hover:text-pen-link-hover ${focus}`,
  alertError: 'rounded-md border border-edge-error-default bg-fill-error-default p-4 text-pen-error-default',
  alertSuccess: 'rounded-md border border-edge-success-default bg-fill-success-default p-4 text-pen-success-default',
  alertInfo: 'rounded-md border border-edge-info-default bg-fill-info-default p-4 text-pen-info-default',
  divider: 'my-4 flex items-center gap-3 text-sm text-pen-muted-default',
  list: 'flex flex-col divide-y divide-edge-base-default',
  listItem: 'flex flex-wrap items-center justify-between gap-3 py-3',
  code: 'font-mono text-base text-pen-base-default',
} as const
