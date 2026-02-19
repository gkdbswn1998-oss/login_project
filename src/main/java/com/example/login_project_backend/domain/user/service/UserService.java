package com.example.login_project_backend.domain.user.service;

import com.example.login_project_backend.domain.user.dto.UserRequestDTO;
import com.example.login_project_backend.domain.user.entity.UserEntity;
import com.example.login_project_backend.domain.user.entity.UserRoleType;
import com.example.login_project_backend.domain.user.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.AccessDeniedException;

@Service
public class UserService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository){
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    //로그인 시 회원 존재 확인
    @Transactional(readOnly = true)
    public Boolean existUser(UserRequestDTO dto){
        return userRepository.existsByUsername(dto.getUsername());
    }

    //자체 로그인 회원가입
    @Transactional
    public Long addUser(UserRequestDTO dto){

        if(userRepository.existsByUsername(dto.getUsername())){
            throw new IllegalArgumentException("이미 유저가 존재합니다");
        }

        UserEntity entity = UserEntity.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .isLock(false)
                .isSocial(false)
                .roleType(UserRoleType.USER)
                .nickname(dto.getNickname())
                .email(dto.getEmail())
                .build();

        return userRepository.save(entity).getId();
    }

    // 자체 로그인
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        UserEntity entity = userRepository.findByUsernameAndIsLockAndIsSocial(username,false,false)
                .orElseThrow(()->new UsernameNotFoundException(username));
        return User.builder()
                .username(entity.getUsername())
                .password(entity.getPassword())
                .roles(entity.getRoleType().name())
                .accountLocked(entity.getIsLock())
                .build();
    }

    // 자체 로그인 회원 정보 수정
    @Transactional
    public Long updateUser(UserRequestDTO dto) throws AccessDeniedException {

        String sessionUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if(!sessionUsername.equals(dto.getUsername())){
            throw new AccessDeniedException("본인 계정만 수정 가능");
        }

        UserEntity entity = userRepository.findByUsernameAndIsLockAndIsSocial(dto.getUsername(), false,false)
                .orElseThrow(()->new UsernameNotFoundException(dto.getUsername()));

        entity.updateUser(dto);

        return userRepository.save(entity).getId();
    }




    // 자체/소셜 로그인 회원 탈퇴

    // 소셜 로그인 (매 로그인시 : 신규 = 가입, 기존 = 업데이트)

    // 자체/소셜 유저 정보 조회


}
