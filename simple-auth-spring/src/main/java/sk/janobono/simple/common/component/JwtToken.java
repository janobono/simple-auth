package sk.janobono.simple.common.component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.JwtConfigProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class JwtToken {

    public record JwtContent(Long id, List<Authority> authorities) {
    }

    private final Algorithm algorithm;
    private final Long expiration;
    private final String issuer;

    public JwtToken(final JwtConfigProperties jwtConfigProperties) {
        final KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(2048);
        final KeyPair keyPair = keyGen.generateKeyPair();
        this.algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        this.expiration = TimeUnit.MINUTES.toMillis(jwtConfigProperties.expiration());
        this.issuer = jwtConfigProperties.issuer();
    }

    public String generateToken(final JwtContent jwtContent, final Long issuedAt) {
        try {
            final JWTCreator.Builder jwtBuilder = JWT.create()
                    .withIssuer(issuer)
                    .withIssuedAt(new Date(issuedAt))
                    .withExpiresAt(new Date(expiresAt(issuedAt)));
            jwtBuilder.withSubject(Long.toString(jwtContent.id()));
            jwtBuilder.withAudience(
                    Optional.ofNullable(jwtContent.authorities()).stream()
                            .flatMap(Collection::stream)
                            .map(Authority::getValue)
                            .toArray(String[]::new)
            );
            return jwtBuilder.sign(algorithm);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public JwtContent parseToken(final String token) {
        final DecodedJWT jwt = decodeToken(token);
        return new JwtContent(
                Long.parseLong(jwt.getSubject()),
                Optional.ofNullable(jwt.getAudience()).stream()
                        .flatMap(Collection::stream)
                        .map(Authority::fromValue)
                        .toList()
        );
    }

    private Long expiresAt(final Long issuedAt) {
        return Optional.ofNullable(issuedAt).map(l -> l + expiration).orElse(0L);
    }

    private DecodedJWT decodeToken(final String token) throws JWTVerificationException {
        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        return verifier.verify(token);
    }
}
