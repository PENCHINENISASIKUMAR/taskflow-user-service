package com.taskflow.userservice.service;

import com.taskflow.userservice.entity.User;
import com.taskflow.userservice.repository.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserAuthenticationTest {
    @Test void authenticatesOnlyMatchingBcryptCredentials() {
        UserRepository repository=mock(UserRepository.class);
        User user=new User(); user.setName("Alex"); user.setEmail("alex@example.com");
        user.setPassword(new BCryptPasswordEncoder().encode("StrongPass123"));
        when(repository.findByEmailIgnoreCase("alex@example.com")).thenReturn(Optional.of(user));
        UserService service=new UserServiceImpl(repository);
        assertEquals("alex@example.com",service.authenticate("Alex@Example.com","StrongPass123").email());
        assertThrows(BadCredentialsException.class,()->service.authenticate("alex@example.com","wrong-password"));
        assertThrows(BadCredentialsException.class,()->service.authenticate("missing@example.com","StrongPass123"));
    }
}
