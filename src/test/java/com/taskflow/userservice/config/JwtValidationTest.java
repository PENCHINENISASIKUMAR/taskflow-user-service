package com.taskflow.userservice.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.time.Instant;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import static org.junit.jupiter.api.Assertions.*;

class JwtValidationTest {
    private final SecretKey key=new SecretKeySpec("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8),"HmacSHA256");
    private final JwtEncoder encoder=new NimbusJwtEncoder(new ImmutableSecret<>(key));
    private final NimbusJwtDecoder decoder=decoder(key);
    private NimbusJwtDecoder decoder(SecretKey secret){NimbusJwtDecoder d=NimbusJwtDecoder.withSecretKey(secret).macAlgorithm(MacAlgorithm.HS256).build();d.setJwtValidator(JwtValidators.createDefaultWithIssuer("taskflow-user-service"));return d;}
    private String token(Instant expiry,SecretKey signingKey){return new NimbusJwtEncoder(new ImmutableSecret<>(signingKey)).encode(JwtEncoderParameters.from(
            JwsHeader.with(MacAlgorithm.HS256).build(),JwtClaimsSet.builder().issuer("taskflow-user-service").subject("7").issuedAt(expiry.minusSeconds(300)).expiresAt(expiry).build())).getTokenValue();}
    @Test void acceptsValidTokenAndRejectsExpiredAndWrongSignature(){
        assertEquals("7",decoder.decode(token(Instant.now().plusSeconds(300),key)).getSubject());
        assertThrows(JwtException.class,()->decoder.decode(token(Instant.now().minusSeconds(300),key)));
        SecretKey other=new SecretKeySpec("abcdefghijklmnopqrstuvwxyz123456".getBytes(StandardCharsets.UTF_8),"HmacSHA256");
        assertThrows(JwtException.class,()->decoder.decode(token(Instant.now().plusSeconds(300),other)));
    }
}
