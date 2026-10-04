/**
 * Utility classes from the SemanticPresentationTheme vocabulary (Theme Manager's
 * tailwind-config.css), shared by the layer's components. Kept as literal
 * strings so Tailwind can find them through tailwind.css. Every state pairs a
 * pen and fill of the same role and state (for example hover with hover), as
 * the theme's contrast guarantees apply only to those pairings.
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
  primaryButton: `inline-flex min-h-11 w-full items-center justify-center rounded-md bg-fill-primary-default px-4 py-2 text-base font-semibold text-pen-primary-default hover:bg-fill-primary-hover hover:text-pen-primary-hover disabled:bg-fill-primary-disabled disabled:text-pen-primary-disabled ${focus}`,
  secondaryButton: `inline-flex min-h-11 items-center justify-center rounded-md border border-edge-secondary-default bg-fill-secondary-default px-4 py-2 text-base font-medium text-pen-secondary-default hover:bg-fill-secondary-hover hover:text-pen-secondary-hover disabled:bg-fill-secondary-disabled ${focus}`,
  dangerButton: `inline-flex min-h-11 items-center justify-center rounded-md border border-edge-error-default bg-fill-error-default px-4 py-2 text-base font-medium text-pen-error-default hover:bg-fill-error-hover hover:text-pen-error-hover ${focus}`,
  toggleButton: `ml-2 inline-flex min-h-6 items-center rounded-sm px-2 text-sm text-pen-link-default underline ${focus}`,
  link: `text-pen-link-default underline hover:text-pen-link-hover ${focus}`,
  // A link standing on its own line: at least 24px tall (WCAG 2.2 target size).
  actionLink: `inline-flex min-h-6 items-center text-pen-link-default underline hover:text-pen-link-hover ${focus}`,
  alertError: 'rounded-md border border-edge-error-default bg-fill-error-default p-4 text-pen-error-default',
  alertSuccess: 'rounded-md border border-edge-success-default bg-fill-success-default p-4 text-pen-success-default',
  alertInfo: 'rounded-md border border-edge-info-default bg-fill-info-default p-4 text-pen-info-default',
  divider: 'my-4 flex items-center gap-3 text-sm text-pen-muted-default',
  list: 'flex flex-col divide-y divide-edge-base-default',
  listItem: 'flex flex-wrap items-center justify-between gap-3 py-3',
  code: 'font-mono text-base tracking-wider text-pen-base-default',
} as const
