package com.market.needa.presentation.user.dto;

import com.market.needa.domain.user.UserRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LoginUserResponseDto {

    private String accessToken;
    private Long userId;
    private String email;
    private String nickname;
    private UserRole role;
}
