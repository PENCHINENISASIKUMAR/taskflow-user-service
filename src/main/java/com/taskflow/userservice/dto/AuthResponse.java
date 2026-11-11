package com.taskflow.userservice.dto;
import java.time.Instant;
public record AuthResponse(Long userId,String name,String email,Instant expiresAt) {}
