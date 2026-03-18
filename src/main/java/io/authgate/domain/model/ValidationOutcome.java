package io.authgate.domain.model;

/**
 * Algebraic data type for token validation results.
 * Sealed — exhaustive pattern matching in Java 21.
 *
 * <pre>{@code
 * switch (outcome) {
 *     case ValidationOutcome.Valid v    -> v.token().hasScope("admin");
 *     case ValidationOutcome.Rejected r -> log.warn(r.reason().description());
 * }
 * }</pre>
 */
public sealed interface ValidationOutcome {

    /** Token is valid. Contains the {@link ValidatedToken} with parsed claims. */
    record Valid(ValidatedToken token) implements ValidationOutcome {}

    /** Token was rejected. Contains the {@link RejectionReason}. */
    record Rejected(RejectionReason reason) implements ValidationOutcome {}
}
