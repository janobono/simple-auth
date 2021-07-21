package sk.janobono.component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;
import sk.janobono.config.ConfigProperties;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
public class JwtToken {

    private final Algorithm algorithm;
    private final Long expiration;
    private final String issuer;

    public JwtToken(ConfigProperties configProperties) {
        this.algorithm = Algorithm.RSA256(
                getPublicKey(configProperties.jwtPublicKey()), getPrivateKey(configProperties.jwtPrivateKey())
        );
        this.expiration = TimeUnit.SECONDS.toMillis(configProperties.jwtExpiration());
        this.issuer = configProperties.issuer();
    }

    private RSAPublicKey getPublicKey(String base64PublicKey) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private RSAPrivateKey getPrivateKey(String base64PrivateKey) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Long expiresAt(Long issuedAt) {
        return issuedAt + expiration;
    }

    public String generateToken(User user, Long issuedAt) {
        try {
            JWTCreator.Builder jwtBuilder = JWT.create()
                    .withIssuer(issuer)
                    .withSubject(user.getUsername())
                    .withClaim("id", user.getId())
                    .withClaim("enabled", user.getEnabled())
                    .withArrayClaim("authorities",
                            user.getAuthorities().stream()
                                    .map(r -> r.getId() + ":" + r.getName())
                                    .collect(Collectors.toSet()).toArray(String[]::new)
                    )
                    .withIssuedAt(new Date(issuedAt))
                    .withExpiresAt(new Date(expiresAt(issuedAt)));
            for (Map.Entry<String, String> entry : user.getAttributes().entrySet()) {
                jwtBuilder.withClaim(issuer + ":" + entry.getKey(), entry.getValue());
            }
            return jwtBuilder.sign(algorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private DecodedJWT decodeToken(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        return verifier.verify(token);
    }

    public User parseToken(String token) {
        DecodedJWT jwt = decodeToken(token);

        User user = new User();
        user.setUsername(jwt.getSubject());
        user.setId(jwt.getClaims().get("id").asLong());
        user.setEnabled(jwt.getClaims().get("enabled").asBoolean());
        String[] authorities = jwt.getClaims().get("authorities").asArray(String.class);
        for (String authority : authorities) {
            String[] strings = authority.split(":");
            user.getAuthorities().add(new Authority(Long.parseLong(strings[0]), strings[1]));
        }
        for (String claimKey : jwt.getClaims().keySet()) {
            if (claimKey.startsWith(issuer + ":")) {
                user.getAttributes().put(
                        claimKey.replaceAll(issuer + ":", ""),
                        jwt.getClaims().get(claimKey).asString()
                );
            }
        }
        return user;
    }
}
