package com.taskflow.userservice.repository;

import com.taskflow.userservice.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class UserRepositoryTest {
    @Autowired UserRepository repository;

    @Test void checksEmailExistence() {
        User user = new User(); user.setName("Alex"); user.setEmail("alex@example.com"); user.setPassword("hash");
        repository.saveAndFlush(user);
        assertTrue(repository.existsByEmail("alex@example.com"));
        assertFalse(repository.existsByEmail("missing@example.com"));
    }
}
