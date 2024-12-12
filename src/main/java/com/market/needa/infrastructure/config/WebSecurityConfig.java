package com.market.needa.infrastructure.config;

import com.market.needa.application.token.TokenService;
import com.market.needa.infrastructure.jwt.TokenAuthenticationFilter;
import com.market.needa.infrastructure.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class WebSecurityConfig {

    /**
     * SecurityFilterChainProxy를 커스터마이징한다.
     *
     * @return WebSecurityCustomizer 객체
     */
    @Bean
    public WebSecurityCustomizer configure() {
        return (web -> web.ignoring()
                .requestMatchers(PathRequest.toH2Console()));
    }

    /**
     * SecurityFilterChain을 구성한다.
     *
     * @param http HttpSecurity 객체
     * @return SecurityFilterChain 객체
     * @throws Exception HttpSecurity 구성 중 오류가 발생할 경우
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, TokenAuthenticationFilter tokenAuthenticationFilter) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                    .requestMatchers("/", "/login", "/signup",
                            "/api/**",
                            "/static/**", "/user/**").permitAll()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter(TokenService tokenService, TokenProvider tokenProvider) {
        return new TokenAuthenticationFilter(tokenProvider, tokenService);
    }

    /**
     * Spring Security의 AuthenticationManager를 리턴한다.
     *
     * @param authenticationConfiguration AuthenticationConfiguration 객체
     * @return AuthenticationConfiguration 객체
     * @throws Exception AuthenticationManager 생성 중 오류가 발생할 경우
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 비밀번호 암호화를 위한 BCryptPasswordEncoder를 리턴한다.
     *
     * @return BCryptPasswordEncoder 객체
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

