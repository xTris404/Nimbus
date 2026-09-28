package vn.iotstar.exceptions;

/** Lỗi xác thực JWT, gói lại các lỗi của Nimbus để tầng trên không phụ thuộc thư viện. */
public class JwtAuthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public enum Reason { MALFORMED, INVALID_SIGNATURE, INVALID_CLAIMS, EXPIRED }

    private final Reason reason;

    public JwtAuthException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public JwtAuthException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
