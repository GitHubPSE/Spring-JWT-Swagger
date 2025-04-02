package com.example.jwtLogin.controller;

import com.example.jwtLogin.dto.LoginDto;
import com.example.jwtLogin.dto.UserDto;
import com.example.jwtLogin.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody UserDto userDto){
        userService.signup(userDto);
        return ResponseEntity.ok("회원가입 완료");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginDto loginDto){
        return ResponseEntity.ok(userService.login(loginDto));
    }

    @GetMapping("/user-info")
    public ResponseEntity<String> userInfo(){
        // SecurityContext 에 저장된 인증 정보 가져오기
        String username = (String)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok("인증된 사용자:" + username);
    }

    @PostMapping("/reissue")
    public ResponseEntity<String> reissue(@RequestBody Map<String, String> request){
        String refreshToken = request.get("refreshToken");
        return ResponseEntity.ok(userService.reissue(refreshToken));
    }
}
