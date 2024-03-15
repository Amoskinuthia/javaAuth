package com.auth.userauth.service;

import com.auth.userauth.model.Role;
import com.auth.userauth.model.User;
import com.auth.userauth.repository.UserRepository;
import com.auth.userauth.request.AuthenticationRequest;
import com.auth.userauth.request.RegistrationRequest;
import com.auth.userauth.response.AuthenticationResponse;
import com.auth.userauth.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    public AuthenticationResponse register(RegistrationRequest registrationRequest) {

        var user = User.builder()
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .firstName(registrationRequest.getFirstName())
                .lastName(registrationRequest.getLastName())
                .role(Role.USER)
                .build();
        userRepository.save(user);

        var jwtToken = jwtUtil.generateToken(user);
        
        return null;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        return null;
    }
}
