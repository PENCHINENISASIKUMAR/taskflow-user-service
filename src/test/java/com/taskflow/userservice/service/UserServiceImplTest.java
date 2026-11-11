package com.taskflow.userservice.service;

import com.taskflow.userservice.dto.UserRegistrationRequest;
import com.taskflow.userservice.entity.User;
import com.taskflow.userservice.exception.DuplicateEmailException;
import com.taskflow.userservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {
    @Mock UserRepository repository;
    @InjectMocks UserServiceImpl service;

    @Test void registrationHashesPasswordAndReturnsNoPassword() {
        when(repository.existsByEmail("a@example.com")).thenReturn(false);
        when(repository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            assertNotEquals("strong-password", user.getPassword());
            assertTrue(user.getPassword().startsWith("$2a$"));
            return user;
        });
        var response = service.register(new UserRegistrationRequest("Alex", "a@example.com", "strong-password"));
        assertEquals("a@example.com", response.email());
        assertFalse(response.toString().contains("strong-password"));
        verify(repository).save(any(User.class));
    }

    @Test void duplicateEmailIsRejected() {
        when(repository.existsByEmail("a@example.com")).thenReturn(true);
        assertThrows(DuplicateEmailException.class, () -> service.register(
                new UserRegistrationRequest("Alex", "a@example.com", "strong-password")));
        verify(repository, never()).save(any());
    }
}
