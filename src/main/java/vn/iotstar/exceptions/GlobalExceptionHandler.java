package vn.iotstar.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private ProblemDetail problem(HttpStatus status, String message, String description) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, message);
        pd.setProperty("description", description);
        return pd;
    }

    // Token sai / hết hạn / giả mạo => chưa xác thực => 401 (slide đang trả 403)
    @ExceptionHandler(JwtAuthException.class)
    public ProblemDetail handleJwt(JwtAuthException ex) {
        String description = switch (ex.getReason()) {
            case EXPIRED -> "The JWT token has expired";
            case INVALID_SIGNATURE -> "The JWT signature is invalid";
            case INVALID_CLAIMS -> "The JWT claims are invalid";
            case MALFORMED -> "The JWT is malformed";
        };
        return problem(HttpStatus.UNAUTHORIZED, "Invalid token", description);
    }

    @ExceptionHandler(AccountStatusException.class)
    public ProblemDetail handleAccountStatus(AccountStatusException ex) {
        return problem(HttpStatus.FORBIDDEN, ex.getMessage(), "The account is locked");
    }

    // BadCredentialsException, UsernameNotFoundException, ...
    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthentication(AuthenticationException ex) {
        return problem(HttpStatus.UNAUTHORIZED, ex.getMessage(), "The username or password is incorrect");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex) {
        return problem(HttpStatus.FORBIDDEN, ex.getMessage(), "You are not authorized to access this resource");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleConflict(DataIntegrityViolationException ex) {
        return problem(HttpStatus.CONFLICT, "Conflict", "Email already exists or data violates a constraint");
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleOthers(Exception ex) {
        log.error("Unhandled exception", ex);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "Unknown internal server error.");
    }
}
