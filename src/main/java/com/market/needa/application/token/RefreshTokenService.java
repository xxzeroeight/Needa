package com.market.needa.application.token;

import com.market.needa.domain.token.RefreshToken;
import com.market.needa.domain.token.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;


    /**
     * 주어진 Refresh Token으로 Refresh Token 객체를 찾는다.
     *
     * @param refreshToken 검색할 Refresh Token 값
     * @return 검색된 Refresh Token 객체
     */
    public RefreshToken findByRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("refreshToken not found"));
    }
}
