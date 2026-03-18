package io.authgate.domain.exception;

import io.authgate.domain.model.RejectionReason;

/**
 * Thrown when a JWT fails validation (expired, bad signature, issuer mismatch, etc.).
 * Maps to HTTP 401 Unauthorized.
 */
public final class TokenValidationException extends AuthGateException {

    private final RejectionReason reason;

    public TokenValidationException(RejectionReason reason) {
        super("Token validation failed: " + reason.description());
        this.reason = reason;
    }

    public TokenValidationException(RejectionReason reason, Throwable cause) {
        super("Token validation failed: " + reason.description(), cause);
        this.reason = reason;
    }

    /** The specific reason the token was rejected. */
    public RejectionReason reason() {
        return reason;
    }
}
