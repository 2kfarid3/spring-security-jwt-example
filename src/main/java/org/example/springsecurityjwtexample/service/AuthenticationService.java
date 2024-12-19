package org.example.springsecurityjwtexample.service;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtexample.dto.RegisterRequest;
import org.example.springsecurityjwtexample.dto.LoginRequest;
import org.example.springsecurityjwtexample.dto.UserResponse;
import org.example.springsecurityjwtexample.ecxeption.AlreadyExistsException;
import org.example.springsecurityjwtexample.entity.User;
import org.example.springsecurityjwtexample.enums.Role;
import org.example.springsecurityjwtexample.repository.UserRepository;
import org.example.springsecurityjwtexample.token.Token;
import org.example.springsecurityjwtexample.token.TokenRepository;
import org.example.springsecurityjwtexample.token.TokenType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final TokenRepository tokenRepository;

    public UserResponse save(RegisterRequest registerRequest) {

        var optionalUser = userRepository.findByUsername(registerRequest.getUsername());
        if (optionalUser.isPresent()) {
            throw new AlreadyExistsException("User already exists!");
        }

        User user = User.builder()
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .nameSurname(registerRequest.getNameSurname())
                .role(Role.USER)
                .build();

        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(savedUser, jwtToken);

        return UserResponse.builder().token(jwtToken).build();
    }

    public UserResponse auth(LoginRequest loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()));

        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow();
        String token = jwtService.generateToken(user);
        revokeUserAllTokens(user);
        saveUserToken(user, token);

        return UserResponse.builder().token(token).build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeUserAllTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUserId(Math.toIntExact(user.getId()));
        if (validUserTokens.isEmpty()) {return;}

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
