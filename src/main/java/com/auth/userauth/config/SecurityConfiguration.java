package com.auth.userauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public JwtAuthFilter jwtAuthFilter(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()

                .requestMatchers( "/api/token/logout/**", "/api/token", "/api/token/refresh-token",
                        "/api/registration", "/api/registration/confirmClientToken", "/api/registration/confirmCoachToken","/api/registration/contact",
                        "/api/registration/reset","/api/registration/forgot","/api/registration/resend",
                        "/api/registration/confirm","*.html")

                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return jwtAuthFilter;
    }

}
