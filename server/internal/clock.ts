import { useAuthenticationClock } from '../utils/authentication-composition'
import { authenticationError } from './http'

/**
 * PRIVATE. The current time from the host's clock (or the system clock).
 *
 * A clock that throws, or answers anything but a valid Date, fails the
 * operation closed as `unavailable`; the layer never falls back to the system
 * clock behind the host's back.
 */
export function currentTime(): Date {
  let value: unknown
  try {
    value = useAuthenticationClock().now()
  }
  catch {
    console.error('[authentication] the clock failed')
    throw authenticationError('unavailable')
  }
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    console.error('[authentication] the clock answered an invalid time')
    throw authenticationError('unavailable')
  }
  // A copy, so nothing the layer does can move the host's clock.
  return new Date(value.getTime())
}
