/**
 * The layer's own message catalogue (en-GB). Hosts override or add locales via
 * `app.config.ts`: `authentication: { messages: { 'en-GB': { ... }, 'cy-GB': { ... } } }`.
 * `{name}` placeholders are replaced from the parameters passed to `t()`.
 */
export const AUTHENTICATION_MESSAGES_EN_GB = {
  // Shared
  'authentication.common.email': 'Email address',
  'authentication.common.password': 'Password',
  'authentication.common.newPassword': 'New password',
  'authentication.common.confirmPassword': 'Confirm new password',
  'authentication.common.currentPassword': 'Current password',
  'authentication.common.passwordHint': 'Use at least {min} characters. A few unrelated words make a strong, memorable password.',
  'authentication.common.showPassword': 'Show password',
  'authentication.common.hidePassword': 'Hide password',
  'authentication.common.passwordsDoNotMatch': 'The passwords do not match.',
  'authentication.common.or': 'or',
  'authentication.common.continue': 'Continue',
  'authentication.common.cancel': 'Cancel',
  'authentication.common.working': 'Please wait…',
  'authentication.common.errorSummary': 'There is a problem',
  'authentication.common.continueWithProvider': 'Continue with {provider}',

  // Sign in
  'authentication.signIn.title': 'Sign in',
  'authentication.signIn.submit': 'Sign in',
  'authentication.signIn.passkey': 'Sign in with a passkey',
  'authentication.signIn.forgotPassword': 'Forgotten your password?',
  'authentication.signIn.noAccount': 'No account yet?',
  'authentication.signIn.createAccount': 'Create an account',
  'authentication.signIn.verified': 'Your email address is confirmed. You can sign in now.',
  'authentication.signIn.verificationFailed': 'That confirmation link is invalid or has expired. Sign in to receive a new one.',
  'authentication.signIn.passwordReset': 'Your password has been changed. Sign in with your new password.',
  'authentication.signIn.secondFactorTitle': 'Two-step verification',
  'authentication.signIn.secondFactorIntro': 'Enter the 6-digit code from your authenticator app.',
  'authentication.signIn.backupCodeIntro': 'Enter one of your backup codes. Each code works once.',
  'authentication.signIn.code': 'Verification code',
  'authentication.signIn.backupCode': 'Backup code',
  'authentication.signIn.verify': 'Verify',
  'authentication.signIn.useBackupCode': 'Use a backup code instead',
  'authentication.signIn.useAuthenticator': 'Use your authenticator app instead',

  // Federation outcomes (?federation=)
  'authentication.federation.cancelled': 'Sign-in with the provider was cancelled.',
  'authentication.federation.link-required': 'We could not sign you in with that provider. If you already have an account, sign in another way and link the provider from your security settings. Otherwise, create an account with your email address.',
  'authentication.federation.link-failed': 'That provider account is already linked to a different account.',
  'authentication.federation.failed': 'Sign-in with the provider did not complete. Please try again.',

  // Sign up
  'authentication.signUp.title': 'Create an account',
  'authentication.signUp.submit': 'Create account',
  'authentication.signUp.haveAccount': 'Already have an account?',
  'authentication.signUp.checkEmail': 'Check your email. If {email} can be used for a new account, we have sent a link to confirm it.',

  // Password recovery
  'authentication.forgotPassword.title': 'Reset your password',
  'authentication.forgotPassword.intro': 'Enter your email address and we will send you a link to choose a new password.',
  'authentication.forgotPassword.submit': 'Send reset link',
  'authentication.forgotPassword.sent': 'If {email} has an account, we have sent a link to reset the password. The link expires in 30 minutes.',
  'authentication.forgotPassword.backToSignIn': 'Back to sign in',
  'authentication.resetPassword.title': 'Choose a new password',
  'authentication.resetPassword.submit': 'Save new password',
  'authentication.resetPassword.missingToken': 'This page needs the link from your password reset email.',

  // MFA
  'authentication.mfa.title': 'Two-step verification',
  'authentication.mfa.enrolIntro': 'Your account needs a second way to confirm it is you. Choose one to continue.',
  'authentication.mfa.stepUpIntro': 'Confirm it is you with your second step to continue.',
  'authentication.mfa.chooseTotp': 'Use an authenticator app',
  'authentication.mfa.choosePasskey': 'Use a passkey',
  'authentication.mfa.totpScan': 'Scan this QR code with your authenticator app, or enter the key below.',
  'authentication.mfa.totpQrLabel': 'QR code for your authenticator app',
  'authentication.mfa.totpKey': 'Setup key',
  'authentication.mfa.totpConfirm': 'Enter the 6-digit code your app shows to finish.',
  'authentication.mfa.backupCodesTitle': 'Save your backup codes',
  'authentication.mfa.backupCodesIntro': 'Each code signs you in once if you lose your device. Store them somewhere safe. They will not be shown again.',
  'authentication.mfa.backupCodesSaved': 'I have saved my backup codes',
  'authentication.mfa.passkeyName': 'Passkey name (optional)',
  'authentication.mfa.passkeyCreate': 'Create a passkey',
  'authentication.mfa.passkeyCreated': 'Passkey created. Now use it to confirm it is you.',
  'authentication.mfa.passkeyUse': 'Use your passkey',
  'authentication.mfa.done': 'Two-step verification is set up.',

  // Security settings
  'authentication.security.title': 'Security',
  'authentication.security.password': 'Password',
  'authentication.security.changePassword': 'Change password',
  'authentication.security.passwordChanged': 'Your password has been changed. Other sessions have been signed out.',
  'authentication.security.twoStep': 'Two-step verification',
  'authentication.security.totpOn': 'Authenticator app: on',
  'authentication.security.totpOff': 'Authenticator app: off',
  'authentication.security.totpSetUp': 'Set up an authenticator app',
  'authentication.security.totpDisable': 'Turn off authenticator app',
  'authentication.security.backupRemaining': 'Backup codes remaining: {count}',
  'authentication.security.backupRegenerate': 'Create new backup codes',
  'authentication.security.passkeys': 'Passkeys',
  'authentication.security.noPasskeys': 'You have no passkeys yet.',
  'authentication.security.passkeyAdd': 'Add a passkey',
  'authentication.security.passkeyRemove': 'Remove {name}',
  'authentication.security.passkeyUnnamed': 'Unnamed passkey',
  'authentication.security.providers': 'Linked sign-in providers',
  'authentication.security.providerLinked': '{provider}: linked',
  'authentication.security.providerLink': 'Link {provider}',
  'authentication.security.providerUnlink': 'Unlink {provider}',
  'authentication.security.sessions': 'Where you are signed in',
  'authentication.security.thisDevice': 'This device',
  'authentication.security.unknownDevice': 'Unknown device',
  'authentication.security.lastActive': 'Last active {time}',
  'authentication.security.sessionRevoke': 'Sign out of {device}',
  'authentication.security.sessionRevokeOthers': 'Sign out everywhere else',
  'authentication.security.signOut': 'Sign out',
  'authentication.security.reauthTitle': 'Confirm it is you',
  'authentication.security.reauthIntro': 'For your security, confirm it is you before changing these settings.',
  'authentication.security.reauthPassword': 'Confirm with password',
  'authentication.security.reauthCode': 'Confirm with code',
  'authentication.security.reauthPasskey': 'Confirm with a passkey',
  'authentication.security.saved': 'Saved.',

  // Errors (contract codes)
  'authentication.error.invalid-credentials': 'The email address or password is not right.',
  'authentication.error.mfa-required': 'Two-step verification is needed to continue.',
  'authentication.error.invalid-mfa-code': 'That code is not right or has already been used.',
  'authentication.error.email-not-verified': 'Confirm your email address first. We have sent you a new link.',
  'authentication.error.password-rejected': 'Choose a different password. It must be at least {min} characters and must not appear in known data breaches.',
  'authentication.error.invalid-or-expired-token': 'That link is invalid or has expired. Request a new one.',
  'authentication.error.reauthentication-required': 'Confirm it is you to continue.',
  'authentication.error.insufficient-assurance': 'This needs a stronger sign-in, such as two-step verification or a passkey that checks it is you.',
  'authentication.error.unauthenticated': 'Your session has ended. Sign in again.',
  'authentication.error.session-expired': 'Your session has ended. Sign in again.',
  'authentication.error.rate-limited': 'Too many attempts. Wait a few minutes and try again.',
  'authentication.error.origin-rejected': 'The request was blocked for your security. Reload the page and try again.',
  'authentication.error.validation-failed': 'Check the details you entered and try again.',
  'authentication.error.unavailable': 'The service is unavailable right now. Try again shortly.',
} as const

export type AuthenticationMessageKey = keyof typeof AUTHENTICATION_MESSAGES_EN_GB
export type AuthenticationMessages = Partial<Record<AuthenticationMessageKey, string>>

/** Replaces `{name}` placeholders; unknown placeholders are left visible so gaps are noticed. */
export function formatMessage(template: string, params: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in params ? String(params[name]) : match))
}

/** Resolves a message for a locale: host override, then the en-GB default, then the key itself. */
export function resolveMessage(
  key: string,
  locale: string,
  overrides: Record<string, AuthenticationMessages | undefined> | undefined,
  params?: Record<string, string | number>,
): string {
  const template = overrides?.[locale]?.[key as AuthenticationMessageKey]
    ?? (AUTHENTICATION_MESSAGES_EN_GB as Record<string, string>)[key]
    ?? key
  return formatMessage(template, params)
}
