package sk.janobono.simple.common.component;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.JsonWebToken;
import sk.janobono.simple.common.config.VerificationConfigProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
public class VerificationToken {

    private final PrivateKey privateKey;
    private final JWTParser jwtParser;
    private final String issuer;

    public VerificationToken(final VerificationConfigProperties verificationConfigProperties) {
        final KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(1024);
        final KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.issuer = verificationConfigProperties.issuer();

        final JWTAuthContextInfo authContextInfo = new JWTAuthContextInfo(keyPair.getPublic(), issuer);
        this.jwtParser = new DefaultJWTParser(authContextInfo);
    }

    public String generateToken(final Map<String, String> data, final Long issuedAt, final Long expiresAt) {
        final JwtClaimsBuilder jwtBuilder = Jwt.claims()
                .issuer(issuer)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt);

        data.forEach(jwtBuilder::claim);

        return jwtBuilder.sign(privateKey);
    }

    public Map<String, String> parseToken(final String token) {
        final JsonWebToken jwt = decodeToken(token);
        final Map<String, String> result = new HashMap<>();
        jwt.getClaimNames().forEach((key) -> result.put(key, jwt.getClaim(key)));
        return result;
    }

    private JsonWebToken decodeToken(final String token) {
        try {
            return jwtParser.parse(token);
        } catch (final ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
