package com.market.needa.application.token;


import com.market.needa.application.user.UserService;
import com.market.needa.domain.user.UserPrincipal;
import com.market.needa.infrastructure.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    /**
     * Refresh Token으로 새 Access Token을 생성한다.
     *
     * @param refreshToken 클라이언트에서 받은 Refresh Token
     * @return 생성된 Refresh Token
     */
    public String createNewAccessToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
        UserPrincipal userPrincipal = userService.findById(userId);

        return tokenProvider.generateToken(userPrincipal, Duration.ofHours(1));
    }
}
