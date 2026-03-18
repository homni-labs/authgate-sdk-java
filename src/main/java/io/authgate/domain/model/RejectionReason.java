package io.authgate.domain.model;

/**
 * Enumeration of reasons why a JWT was rejected during validation.
 *
 * <p>Each reason carries a machine-readable {@link #code()} (e.g. {@code "token_expired"})
 * and a human-readable {@link #description()} (e.g. {@code "Token has expired"}).</p>
 */
public enum RejectionReason {

    TOKEN_EXPIRED("token_expired", "Token has expired"),
    INVALID_SIGNATURE("invalid_signature", "Token signature is invalid"),
    ISSUER_MISMATCH("issuer_mismatch", "Token issuer does not match expected issuer"),
    AUDIENCE_MISMATCH("audience_mismatch", "Token audience does not match expected audience"),
    MALFORMED_TOKEN("malformed_token", "Token is malformed or cannot be parsed"),
    UNKNOWN("unknown", "Unknown validation failure");

    private final String code;
    private final String description;

    RejectionReason(String code, String description) {
        this.code = code;
        this.description = description;
    }

    /** Machine-readable error code, e.g. {@code "token_expired"}. */
    public String code() {
        return code;
    }

    /** Human-readable description, e.g. {@code "Token has expired"}. */
    public String description() {
        return description;
    }
}
