package vn.iotstar.services;

import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;
import vn.iotstar.exceptions.JwtAuthException;
import vn.iotstar.exceptions.JwtAuthException.Reason;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKeyBase64;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.issuer}")
    private String issuer;

    private JWSSigner signer;
    private JWSVerifier verifier;

    /** Fail-fast: secret yếu thì app không được khởi động. HS256 yêu cầu >= 256 bit. */
    @PostConstruct
    void init() throws JOSEException {
        byte[] secret = Base64.getDecoder().decode(secretKeyBase64.trim());
        if (secret.length < 32) {
            throw new IllegalStateException("security.jwt.secret-key must decode to at least 32 bytes (256 bits)");
        }
        this.signer = new MACSigner(secret);     // thread-safe
        this.verifier = new MACVerifier(secret); // thread-safe
    }

    // ------------------------------------------------------------ tạo token
    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Instant now = Instant.now();

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        // private claims đặt TRƯỚC, để chúng không ghi đè được các registered claims bên dưới
        extraClaims.forEach(claims::claim);
        claims.subject(userDetails.getUsername())
              .issuer(issuer)
              .issueTime(Date.from(now))
              .expirationTime(Date.from(now.plusMillis(jwtExpiration))) // dùng đúng cấu hình, không hardcode
              .jwtID(UUID.randomUUID().toString());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
        return jwt.serialize();
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    // ------------------------------------------------- parse + verify (1 lần)
    /**
     * Thứ tự: parse -> ghim thuật toán -> verify chữ ký -> kiểm tra claims.
     * Chỉ đọc claims SAU KHI chữ ký đã được xác minh.
     */
    public JWTClaimsSet parseAndVerify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token); // token dạng "alg=none" (PlainJWT) sẽ bị từ chối ở đây

            // Ghim thuật toán: không tin "alg" do client gửi
            if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())) {
                throw new JwtAuthException(Reason.INVALID_SIGNATURE, "Unexpected JWS algorithm");
            }
            if (!jwt.verify(verifier)) {
                throw new JwtAuthException(Reason.INVALID_SIGNATURE, "Signature verification failed");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            if (!issuer.equals(claims.getIssuer())) {
                throw new JwtAuthException(Reason.INVALID_CLAIMS, "Unexpected issuer");
            }
            Date exp = claims.getExpirationTime();
            if (exp == null) {
                throw new JwtAuthException(Reason.INVALID_CLAIMS, "Missing exp claim");
            }
            if (exp.before(new Date())) {
                throw new JwtAuthException(Reason.EXPIRED, "Token expired");
            }
            return claims;
        } catch (ParseException e) {
            throw new JwtAuthException(Reason.MALFORMED, "Malformed token", e);
        } catch (JOSEException e) {
            throw new JwtAuthException(Reason.INVALID_SIGNATURE, "Cannot verify token", e);
        }
    }
}
