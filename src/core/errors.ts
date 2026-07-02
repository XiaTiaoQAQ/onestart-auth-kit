// SDK 自有错误类型,业务层各自映射到自己的错误码体系(m612 BusinessError / rensheji ApiError)。

export type AuthErrorKind =
  | 'credential_invalid'
  | 'code_invalid'
  | 'code_rate_limited'
  | 'provider_not_configured'
  | 'provider_upstream'
  | 'account_locked'
  | 'user_blocked'
  | 'token_invalid'
  | 'token_expired'
  | 'token_revoked'
  | 'identity_taken'
  | 'contact_taken'
  | 'identity_not_found'
  | 'last_identity'
  | 'user_not_found'
  | 'password_required'

export class AuthError extends Error {
  constructor(
    readonly kind: AuthErrorKind,
    readonly detail: Record<string, unknown> = {},
  ) {
    super(kind)
    this.name = 'AuthError'
  }
}

export function isAuthError(err: unknown, kind?: AuthErrorKind): err is AuthError {
  return err instanceof AuthError && (kind === undefined || err.kind === kind)
}
