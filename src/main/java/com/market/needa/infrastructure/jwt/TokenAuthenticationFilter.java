package com.market.needa.infrastructure.jwt;

import com.market.needa.application.token.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final TokenService tokenService;

    private final static String HEADER_AUTHORIZATION = "Authorization";
    private final static String TOKEN_PREFIX = "Bearer ";

    /**
     * JWT 인증 필터로, HTTP 요청의 Access Token을 검증하고 사용자 인증을 설정한다.
     *
     * 요청의 Header에서 Access Token을 추출하고, 토큰이 유효한 경우 SecurityContextHolder에 인증 정보를 등록한다.
     * 만약 Access Token이 유효하지 않으면 Refresh Token을 사용해 새로운 Access Token을 재발급한다.
     *
     * @param request 클라이언트로부터의 HTTP 요청
     * @param response 클라이언트로 보낼 HTTP 응답
     * @param filterChain 다음 필터로 요청과 응답을 전달하는 체인
     * @throws ServletException 필터 실행 중 서블릿 예외가 발생할 경우
     * @throws IOException 필터 실행 중 입출력 예외가 발생할 경우
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 클라이언트가 보낸 Header에 Access Token을 가져온다.
        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);
        // 파싱한 Access Token을 가져온다.
        String token = getAccessToken(authorizationHeader);

        try {
            // 토큰이 존재하며, 유효성 검사를 통과하면 SecurityContextHolder에 등록한다.
            if (token != null && tokenProvider.validateToken(token)) {
                Authentication authentication = tokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                // 새로운 Access Token을 발급한다.
                token = reissueAccessToken(request, response);

                // 새로운 Access Token을 SecurityContextHolder에 등록한다.
                if (token != null) {
                    Authentication authentication = tokenProvider.getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Refresh Token을 사용해 새로운 Access Token을 재발급한다.
     *
     * @param request 클라이언트로부터의 HTTP 요청
     * @param response 클라이언트로 보낼 HTTP 응답
     * @return 새롭게 발급된 Access Token or null
     */
    private String reissueAccessToken(HttpServletRequest request, HttpServletResponse response) {
        // 쿠키에서 Refresh Token을 가져온다.
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        // 가져온 Refresh Token을 검증하여 새로운 Access Token을 재발급한다.
        if (refreshToken != null) {
            try {
                if (tokenProvider.validateToken(refreshToken)) {
                    return tokenService.createNewAccessToken(refreshToken);
                } else {
                    // 쿠키를 삭제하여 유효하지 않은 토큰이 남아있는 것을 방지한다.
                    Cookie cookie = new Cookie("refresh_token", null);
                    cookie.setMaxAge(0);
                    cookie.setPath("/");
                    cookie.setHttpOnly(true);
                    response.addCookie(cookie);

                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }

        return null;
    }

    /**
     * Authorization 헤더에서 Access Token을 추출한다.
     *
     * @param authorizationHeader 요청 헤더에서 가져온 Authorization 값
     * @return 파싱된 Access Token 문자열 or null
     */
    private String getAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }
        return null;
    }
}
