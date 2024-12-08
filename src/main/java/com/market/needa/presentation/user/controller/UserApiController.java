package com.market.needa.presentation.user.controller;

import com.market.needa.application.token.TokenService;
import com.market.needa.application.user.UserService;
import com.market.needa.domain.user.User;
import com.market.needa.domain.user.UserPrincipal;
import com.market.needa.infrastructure.jwt.TokenProvider;
import com.market.needa.presentation.user.dto.CreateUserRequestDto;
import com.market.needa.presentation.user.dto.LoginUserRequestDto;
import com.market.needa.presentation.user.dto.LoginUserResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RequiredArgsConstructor
@RestController
public class UserApiController {

    private final UserService userService;
    private final TokenService tokenService;
    private final TokenProvider tokenProvider;

    /**
     * 사용자의 회원가입 요청을 처리한다.
     *
     * @param createUserRequestDto 회원가입에 필요한 사용자 정보를 담은 DTO
     * @return 201(Created) 상태 코드
     */
    @PostMapping("/api/signup")
    public ResponseEntity<Void> signup(@RequestBody CreateUserRequestDto createUserRequestDto) {
        userService.save(createUserRequestDto);

        return ResponseEntity.status(HttpStatus.CREATED)
                .build();
    }

    /**
     * 사용자의 로그인 요청을 처리한다.
     *
     * @param loginUserRequestDto 로그인 요청 정보를 담고 있는 DTO
     * @return 로그인 결과, 사용자 정보, Access Token, Refresh Token
     */
    @PostMapping("/api/login")
    public ResponseEntity<LoginUserResponseDto> login(@RequestBody LoginUserRequestDto loginUserRequestDto) {
        User user = userService.login(loginUserRequestDto);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // UserPrincipal
        UserPrincipal userPrincipal = createUserPrincipal(user);

        // generateToken
        String accessToken = tokenProvider.generateToken(userPrincipal, Duration.ofHours(1));
        String refreshToken = tokenProvider.generateToken(userPrincipal, Duration.ofDays(1));

        // LoginUserResponseDto
        LoginUserResponseDto loginUserResponseDto = LoginUserResponseDto.builder()
                .accessToken(accessToken)
                .userId(user.getId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .role(user.getRole())
                .build();

        // RefreshToken Cookie
        ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ofDays(1))
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(loginUserResponseDto);
    }

    private UserPrincipal createUserPrincipal(User user) {
        return new UserPrincipal(
                User.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .nickname(user.getNickname())
                        .role(user.getRole())
                        .build()
        );
    }
}

