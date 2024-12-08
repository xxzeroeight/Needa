package com.market.needa.infrastructure.jwt;

import com.market.needa.domain.user.User;
import com.market.needa.domain.user.UserPrincipal;
import com.market.needa.domain.user.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Duration;
import java.util.Date;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    /**
     * 사용자의 토큰을 생성한다.
     *
     * @param userPrincipal 사용자 정보를 담고 있는 UserPrincipal 객체
     * @param expireAt 토큰 만료 시간
     * @return 토큰 문자열
     */
    public String generateToken(UserPrincipal userPrincipal, Duration expireAt) {
        Date now = new Date();

        return makeToken(new Date(now.getTime() + expireAt.toMillis()), userPrincipal); // 현재 시간 + 만료 시간(지정)
    }

    /**
     * JWT 토큰을 생성하고 문자열 형태로 리턴한다.
     *
     * @param expiry 토큰 만료 시각
     * @param userPrincipal 사용자 정보를 담고 있는 UserPrincipal 객체
     * @return 토큰 문자열
     */
    private String makeToken(Date expiry, UserPrincipal userPrincipal) {
        Date now = new Date();

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE) // 헤더 타입 - "typ": "JWT"
                .setIssuer(jwtProperties.getIssuer())         // 발급자 - "iss": "www.needa.com"
                .setIssuedAt(now)                             // 발급 시간 - "iat": "1698329400"
                .setExpiration(expiry)                        // 만료 시간 - "exp": "1698333000"
                .setSubject(userPrincipal.getUsername())      // 식별자 - "sub": "xxzeroeight@naver.com"
                .claim("id", userPrincipal.getId())        // 사용자 id - "id": "12345"
                .signWith(SECRET_KEY)                         // 서명 - "signature": "..."
                .compact();                                   // 문자열 형태로 압축 - <header>.<payload>.<signature>
    }

    /**
     * 토큰의 유효성을 검증한다.
     *
     * @param token 검증할 토큰
     * @return 토큰이 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰에서 인증정보를 생성한다.
     *
     * @param token 토큰
     * @return Authentication 객체, 인증된 사용자 정보와 권한이 포함됨
     */
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        String email = claims.getSubject();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("user not found" + email));

        UserPrincipal userPrincipal = new UserPrincipal(user);

        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                "",
                userPrincipal.getAuthorities()
        );
    }

    /**
     * 토큰에서 사용자 ID를 추출한다.
     *
     * @param token 토큰
     * @return 사용자 ID
     */
    public Long getUserId(String token) {
        Claims claims = getClaims(token);

        return claims.get("id", Long.class);
    }

    /**
     * 토큰을 복호화하여 클레임을 가져온다.
     *
     * @param token 토큰
     * @return Claims 객체, 토큰의 페이로드 데이터를 포함
     */
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
