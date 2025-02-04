package com.ecolink.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ecolink.spring.security.jwt.JwtAuthorizationFilter;
import com.ecolink.spring.security.jwt.JwtProvider;
import com.ecolink.spring.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Sólo si necesitas usar @PreAuthorize, @PostAuthorize, etc.
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /**
     * Codificador de contraseñas.
     */
    @Bean
    public BCryptPasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define el filtro JWT como un @Bean, inyectando lo que necesite (JwtProvider y tu servicio de usuarios).
     */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter(JwtProvider tokenProvider,
                                                        CustomUserDetailsService userDetailsService) {
        return new JwtAuthorizationFilter(tokenProvider, userDetailsService);
    }

    /**
     * Configura la cadena de filtros de Spring Security.
     * El JwtAuthorizationFilter se inyecta por parámetro (ya definido como @Bean).
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtAuthorizationFilter jwtAuthorizationFilter) throws Exception {
        http
            .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                // Endpoints permitidos sin autenticación
                .requestMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
                .requestMatchers("/h2-console/**", "/swagger-ui/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/product", "/api/startup", "/api/post", "/api/ods").permitAll()

                // Endpoints restringidos
                .requestMatchers(HttpMethod.GET, "/api/mission").hasAuthority("CLIENT")
                .requestMatchers(HttpMethod.GET, "/api/challenge").hasAnyAuthority("COMPANY", "STARTUP")

                // Cualquier otro endpoint requiere autenticación
                .anyRequest().authenticated()
            )
            // Deshabilita CSRF para uso de JWT (stateless)
            .csrf(csrf -> csrf.disable())

            // Permite frames para H2 Console
            .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()))

            // Config opcional de logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/public")
                .invalidateHttpSession(true)
                .permitAll()
            );

        // Agrega el filtro JWT antes del UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * AuthenticationManager para inyectarlo en tu servicio de autenticación.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(getPasswordEncoder());
        authProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(authProvider);
    }
}
