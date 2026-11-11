package com.taskflow.userservice.controller;

import com.taskflow.userservice.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import org.springframework.test.context.TestPropertySource;
import org.springframework.context.annotation.Import;
import com.taskflow.userservice.config.SecurityConfig;
import com.taskflow.userservice.config.SecurityErrorHandlers;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@TestPropertySource(properties="taskflow.jwt.secret-base64=VGhpcy1pcy1hLXRlc3Qta2V5LWZvci1qd3QtMzItYnl0ZXM=")
@Import({SecurityConfig.class, SecurityErrorHandlers.class})
class UserControllerTest {
    @Autowired MockMvc mvc;
    @MockBean UserService service;

    @Test void rejectsInvalidRegistrationBeforeCallingService() throws Exception {
        mvc.perform(post("/api/users").contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"\",\"email\":\"bad\",\"password\":\"short\"}").with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.name").exists())
                .andExpect(jsonPath("$.path").value("/api/users"));
    }
}
