package com.taskflow.userservice.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import jakarta.servlet.http.Cookie;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration @EnableWebSecurity @EnableMethodSecurity
public class SecurityConfig {
    @Bean SecretKey jwtSecret(@Value("${taskflow.jwt.secret-base64}") String encoded) {
        byte[] bytes;
        try { bytes=Base64.getDecoder().decode(encoded); } catch (IllegalArgumentException e) { throw new IllegalStateException("JWT_SECRET_BASE64 must be valid Base64",e); }
        if(bytes.length<32) throw new IllegalStateException("JWT_SECRET_BASE64 must decode to at least 32 bytes");
        return new SecretKeySpec(bytes,"HmacSHA256");
    }
    @Bean JwtDecoder jwtDecoder(SecretKey key) {
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("taskflow-user-service")); return decoder;
    }
    @Bean JwtEncoder jwtEncoder(SecretKey key) { return new NimbusJwtEncoder(new ImmutableSecret<>(key)); }
    @Bean BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver header=new DefaultBearerTokenResolver();
        return request -> {
            String path = request.getRequestURI();
            String method = request.getMethod();
            boolean publicAuthRequest = "OPTIONS".equals(method)
                    || ("GET".equals(method) && "/api/auth/csrf".equals(path))
                    || ("POST".equals(method) && ("/api/auth/register".equals(path)
                        || "/api/auth/login".equals(path) || "/api/users/register".equals(path)));
            if (publicAuthRequest) return null;
            String token=header.resolve(request); if(token!=null)return token; Cookie[] cookies=request.getCookies(); if(cookies!=null)for(Cookie cookie:cookies)if("TASKFLOW_ACCESS".equals(cookie.getName()))return cookie.getValue(); return null;
        };
    }
    @Bean CsrfTokenRepository csrfTokenRepository() { CookieCsrfTokenRepository repo=CookieCsrfTokenRepository.withHttpOnlyFalse(); repo.setCookieName("XSRF-TOKEN"); repo.setHeaderName("X-XSRF-TOKEN"); repo.setCookiePath("/"); return repo; }
    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,BearerTokenResolver resolver,CsrfTokenRepository csrf,
            AuthenticationEntryPoint entryPoint,AccessDeniedHandler denied) throws Exception {
        RequestMatcher bearerCsrfExemption=request -> { String value=request.getHeader("Authorization"); return value!=null && value.regionMatches(true,0,"Bearer ",0,7); };
        http.cors(Customizer.withDefaults()).csrf(c->c.csrfTokenRepository(csrf).csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()).ignoringRequestMatchers(bearerCsrfExemption))
            .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(e->e.authenticationEntryPoint(entryPoint).accessDeniedHandler(denied))
            .authorizeHttpRequests(a->a.requestMatchers("/v3/api-docs/**","/swagger-ui/**","/swagger-ui.html","/actuator/health").permitAll()
                .requestMatchers(HttpMethod.GET,"/api/auth/csrf").permitAll()
                .requestMatchers("/api/auth/login","/api/auth/register","/api/users","/api/users/register").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(o->o.bearerTokenResolver(resolver).jwt(Customizer.withDefaults()).authenticationEntryPoint(entryPoint).accessDeniedHandler(denied));
        return http.build();
    }
}
