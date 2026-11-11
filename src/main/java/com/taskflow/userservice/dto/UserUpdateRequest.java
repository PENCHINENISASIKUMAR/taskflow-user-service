package com.taskflow.userservice.dto; import jakarta.validation.constraints.*; public record UserUpdateRequest(@NotBlank @Size(max=100) String name,@NotBlank @Email @Size(max=190) String email) {}
