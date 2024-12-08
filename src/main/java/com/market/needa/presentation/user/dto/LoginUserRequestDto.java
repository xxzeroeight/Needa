package com.market.needa.presentation.user.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoginUserRequestDto {

    private String email;
    private String password;
}
