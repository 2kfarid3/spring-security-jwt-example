package org.example.springsecurityjwtexample.controller;

import org.example.springsecurityjwtexample.dto.RegisterRequest;
import org.example.springsecurityjwtexample.dto.LoginRequest;
import org.example.springsecurityjwtexample.dto.UserResponse;
import org.example.springsecurityjwtexample.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/save")
    public ResponseEntity<UserResponse> save(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authenticationService.save(registerRequest));
    }

    @PostMapping("/auth")
    public ResponseEntity<UserResponse> auth(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authenticationService.auth(loginRequest));
    }


}
