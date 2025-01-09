package sk.janobono.simple.common.component;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.JsonWebToken;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.JwtConfigProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@ApplicationScoped
public class JwtToken {

    public record JwtContent(Long id, List<Authority> authorities) {
    }

    private final PrivateKey privateKey;
    private final JWTParser jwtParser;

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
        this.privateKey = keyPair.getPrivate();
        this.expiration = TimeUnit.MINUTES.toMillis(jwtConfigProperties.expiration());
        this.issuer = jwtConfigProperties.issuer();

        final JWTAuthContextInfo authContextInfo = new JWTAuthContextInfo(keyPair.getPublic(), issuer);
        this.jwtParser = new DefaultJWTParser(authContextInfo);
    }

    public String generateToken(final JwtContent jwtContent, final Long issuedAt) {
        return Jwt.claims()
                .issuer(issuer)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt(issuedAt))
                .subject(Long.toString(jwtContent.id()))
                .audience(Optional.ofNullable(jwtContent.authorities()).stream()
                        .flatMap(Collection::stream)
                        .map(Authority::toString)
                        .collect(Collectors.toSet()))
                .sign(privateKey);
    }

    public JwtContent parseToken(final String token) {
        final JsonWebToken jwt = decodeToken(token);
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

    private JsonWebToken decodeToken(final String token) {
        try {
            return jwtParser.parse(token);
        } catch (final ParseException e) {
            throw new RuntimeException(e);
        }
    }
}
