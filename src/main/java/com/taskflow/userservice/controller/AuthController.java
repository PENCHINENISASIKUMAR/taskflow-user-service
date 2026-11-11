package com.taskflow.userservice.controller;

import com.taskflow.userservice.dto.AuthResponse;
import com.taskflow.userservice.dto.LoginRequest;
import com.taskflow.userservice.dto.UserRegistrationRequest;
import com.taskflow.userservice.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.security.web.csrf.CsrfToken;
import java.util.Map;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final String COOKIE = "TASKFLOW_ACCESS";
    private final UserService service;
    private final JwtEncoder encoder;
    private final long ttlSeconds;
    private final boolean secureCookie;

    public AuthController(UserService service, JwtEncoder encoder,
            @Value("${taskflow.jwt.expiration-seconds:3600}") long ttlSeconds,
            @Value("${taskflow.jwt.cookie-secure:false}") boolean secureCookie) {
        this.service = service; this.encoder = encoder; this.ttlSeconds = ttlSeconds; this.secureCookie = secureCookie;
    }

    @GetMapping("/csrf")
    public Map<String,String> csrf(CsrfToken token) { return Map.of("token", token.getToken()); }

    @PostMapping("/register")
    @org.springframework.web.bind.annotation.ResponseStatus(org.springframework.http.HttpStatus.CREATED)
    public com.taskflow.userservice.dto.UserResponse register(@Valid @RequestBody UserRegistrationRequest request) {
        return service.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        var user = service.authenticate(request.email(), request.password());
        Instant now = Instant.now(); Instant expires = now.plusSeconds(ttlSeconds);
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer("taskflow-user-service").issuedAt(now).expiresAt(expires)
                .subject(user.id().toString()).claim("email", user.email()).claim("name", user.name())
                .claim("roles", List.of("USER")).build();
        String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(COOKIE, token).httpOnly(true).secure(secureCookie)
                .sameSite("Strict").path("/").maxAge(ttlSeconds).build().toString());
        return new AuthResponse(user.id(), user.name(), user.email(), expires);
    }

    @GetMapping("/me")
    public AuthResponse me(@AuthenticationPrincipal Jwt jwt) {
        return new AuthResponse(Long.valueOf(jwt.getSubject()), jwt.getClaimAsString("name"),
                jwt.getClaimAsString("email"), jwt.getExpiresAt());
    }

    @PostMapping("/logout")
    public org.springframework.http.ResponseEntity<Void> logout() {
        return org.springframework.http.ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE,
                ResponseCookie.from(COOKIE, "").httpOnly(true).secure(secureCookie).sameSite("Strict").path("/").maxAge(0).build().toString()).build();
    }
}
