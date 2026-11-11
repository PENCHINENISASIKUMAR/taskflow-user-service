package com.taskflow.userservice.controller;

import com.taskflow.userservice.dto.UserResponse;
import com.taskflow.userservice.service.UserService;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.context.annotation.Import;
import com.taskflow.userservice.config.SecurityConfig;
import com.taskflow.userservice.config.SecurityErrorHandlers;
import org.springframework.test.web.servlet.MockMvc;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@TestPropertySource(properties="taskflow.jwt.secret-base64=VGhpcy1pcy1hLXRlc3Qta2V5LWZvci1qd3QtMzItYnl0ZXM=")
@Import({SecurityConfig.class, SecurityErrorHandlers.class})
class AuthControllerTest {
    @Autowired MockMvc mvc;
    @MockBean UserService service;

    @Test void successfulLoginSetsHttpOnlyCookieAndDoesNotReturnToken() throws Exception {
        when(service.authenticate(anyString(), anyString())).thenReturn(new UserResponse(42L,"Alex","alex@example.com",LocalDateTime.now(),LocalDateTime.now()));
        mvc.perform(post("/api/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alex@example.com\",\"password\":\"StrongPass123\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("TASKFLOW_ACCESS=")))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("HttpOnly")))
                .andExpect(jsonPath("$.userId").value(42))
                .andExpect(jsonPath("$.accessToken").doesNotExist());
    }
}
