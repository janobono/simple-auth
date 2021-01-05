package sk.janobono.component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import sk.janobono.config.ConfigProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
public class JwtToken {

    @Getter
    @Setter
    @ToString
    public static class JwtUser implements UserDetails {

        private String username;

        private Boolean enabled;

        private Set<String> roles;

        private Map<String, String> attributes;

        public Set<String> getRoles() {
            if (roles == null) {
                roles = new HashSet<>();
            }
            return roles;
        }

        public Map<String, String> getAttributes() {
            if (attributes == null) {
                attributes = new HashMap<>();
            }
            return attributes;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        }

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }
    }

    private final Algorithm algorithm;
    private final Long expiration;
    private final String issuer;

    public JwtToken(ConfigProperties configProperties) {
        this.algorithm = Algorithm.RSA256(
                getPublicKey(configProperties.getJwtPublicKey()), getPrivateKey(configProperties.getJwtPrivateKey())
        );
        this.expiration = TimeUnit.SECONDS.toMillis(configProperties.getJwtExpiration());
        this.issuer = configProperties.getIssuer();
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

    public String generateToken(JwtUser user, Long issuedAt) {
        try {
            JWTCreator.Builder jwtBuilder = JWT.create()
                    .withIssuer(issuer)
                    .withSubject(user.getUsername())
                    .withClaim("enabled", user.getEnabled())
                    .withArrayClaim("authorities", user.getRoles().toArray(String[]::new))
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

    public JwtUser parseToken(String token) throws Exception {
        DecodedJWT jwt = decodeToken(token);

        JwtUser user = new JwtUser();
        user.setUsername(jwt.getSubject());
        user.setEnabled(jwt.getClaims().get("enabled").asBoolean());
        String[] authorities = jwt.getClaims().get("authorities").asArray(String.class);
        for (String role : authorities) {
            user.getRoles().add(role);
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
