package com.example.jwtLogin.service;

import com.example.jwtLogin.dto.LoginDto;
import com.example.jwtLogin.dto.UserDto;
import com.example.jwtLogin.entity.User;
import com.example.jwtLogin.repository.UserRepository;
import com.example.jwtLogin.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public void signup(UserDto userDto){
        // 중복 체크
        if(userRepository.findByUsername(userDto.getUsername()).isPresent()){
            throw new RuntimeException("이미 존재하는 사용자입니다.");
        }

        // 유저 저장
        User user = new User();
        user.setUsername(userDto.getUsername());
        // 패스워드 암호화
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        userRepository.save(user);
    }

    public Map<String, String> login(LoginDto loginDto){
        // 사용자 찾기
        User user = userRepository.findByUsername(loginDto.getUsername())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 사용자입니다."));

        // 비밀번호 찾기
        if (!passwordEncoder.matches(loginDto.getPassword(), user.getPassword())){
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        // Access Token & Refresh Token 발급
        String accessToken = jwtUtil.generateToken(user.getUsername());
        String refreshToken = jwtUtil.generateToken(user.getUsername());

        // Refresh Token 저장
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        // 둘 다 반환
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);
        return tokenMap;
    }

    public String reissue(String refreshToken){
        User user = userRepository.findByRefreshToken(refreshToken).orElseThrow(()-> new RuntimeException("유효하지 않는 Refresh Toekn 입니다."));

        return jwtUtil.generateToken(user.getUsername()); // 새 Access Token 발급
    }
}
