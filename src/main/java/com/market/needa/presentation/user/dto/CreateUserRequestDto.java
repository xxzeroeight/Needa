package com.market.needa.presentation.user.dto;

import com.market.needa.domain.user.User;
import com.market.needa.domain.user.UserRole;
import lombok.Getter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
public class CreateUserRequestDto {

    private String nickname;
    private String email;
    private String password;

    public User toEntity(PasswordEncoder passwordEncoder) {
        return User.builder()
                .nickname(nickname)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(UserRole.ROLE_USER)
                .build();
    }
}
