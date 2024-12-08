package com.market.needa.application.user;

import com.market.needa.domain.user.User;
import com.market.needa.domain.user.UserPrincipal;
import com.market.needa.domain.user.UserRepository;
import com.market.needa.presentation.user.dto.CreateUserRequestDto;
import com.market.needa.presentation.user.dto.LoginUserRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 전달받은 유저 ID로 유저를 검색해서 전달한다.
     *
     * @param userId 사용자의 ID
     * @return 검색된 유저의 인증 정보
     */
    public UserPrincipal findById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(String.valueOf(userId)));

        return new UserPrincipal(user);
    }

    /**
     * DTO로 받은 정보로 사용자를 저장한다.
     *
     * @param createUserRequestDto 사용자 생성 요청 정보를 담은 DTO
     */
    @Transactional
    public void save(CreateUserRequestDto createUserRequestDto) {
        User savedUser = createUserRequestDto.toEntity(bCryptPasswordEncoder);

        userRepository.save(savedUser);
    }

    /**
     * 로그인(email, password)하는 메서드이다.
     *
     * @param loginUserRequestDto 로그인 요청 정보를 담은 DTO
     * @return 인증된 사용자 정보를 포함하는 User 객체
     */
    public User login(LoginUserRequestDto loginUserRequestDto) {
        User user = userRepository.findByEmail(loginUserRequestDto.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("등록되지 않은 이메일입니다."));

        if (!bCryptPasswordEncoder.matches(loginUserRequestDto.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        return user;
    }
}
