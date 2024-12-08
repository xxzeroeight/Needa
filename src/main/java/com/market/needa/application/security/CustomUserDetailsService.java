package com.market.needa.application.security;

import com.market.needa.domain.user.User;
import com.market.needa.domain.user.UserPrincipal;
import com.market.needa.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 주어진 이메일로 사용자 정보를 얻는다.
     *
     * @param email 사용자의 이메일 주소
     * @return 사용자의 인증 정보를 담고 있는 객체
     * @throws UsernameNotFoundException 주어진 이메일로 해당 사용자를 찾을 수 없을 때 발생
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        return new UserPrincipal(user);
    }
}
