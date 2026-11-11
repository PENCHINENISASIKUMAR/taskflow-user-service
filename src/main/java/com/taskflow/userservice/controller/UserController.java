package com.taskflow.userservice.controller;

import com.taskflow.userservice.dto.*;
import com.taskflow.userservice.service.UserService;
import jakarta.validation.Valid;
import org.slf4j.*;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController

@RequestMapping("/api/users")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final UserService service;

    public UserController(UserService s) {
        service = s;
    }

    @PostMapping({"", "/register"})
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody UserRegistrationRequest r) {
        return service.register(r);
    }

    @GetMapping("/{id}")
    public UserResponse get(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        requireSelf(id, jwt); return service.getById(id);
    }

    @GetMapping
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    public List<UserResponse> all() {
        return service.getAll();
    }

    @PutMapping("/{id}")
    public UserResponse update(@PathVariable Long id, @Valid @RequestBody UserUpdateRequest r, @AuthenticationPrincipal Jwt jwt) {
        requireSelf(id, jwt); log.info("Updating user {}", id);
        return service.update(id, r);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        requireSelf(id, jwt); log.info("Deleting user {}", id);
        service.delete(id);
    }

    private void requireSelf(Long id, Jwt jwt) { if (!id.toString().equals(jwt.getSubject())) throw new AccessDeniedException("Users may only access their own profile"); }

    @GetMapping("/exists")
    public Map<String, Boolean> exists(@RequestParam @jakarta.validation.constraints.Email String email) {
        return Map.of("exists", service.emailExists(email));
    }
}
