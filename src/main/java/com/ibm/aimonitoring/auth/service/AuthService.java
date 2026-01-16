package com.ibm.aimonitoring.auth.service;

import com.ibm.aimonitoring.auth.dto.*;
import com.ibm.aimonitoring.auth.model.RefreshToken;
import com.ibm.aimonitoring.auth.model.User;
import com.ibm.aimonitoring.auth.repository.RefreshTokenRepository;
import com.ibm.aimonitoring.auth.repository.UserRepository;
import com.ibm.aimonitoring.auth.security.JwtTokenProvider;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    
    @PersistenceContext
    private EntityManager entityManager;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());

        user = userRepository.save(user);
        
        // Assign USER role by inserting into user_roles table
        assignRoleToUser(user.getId(), "USER");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        String token = tokenProvider.generateToken(authentication, user);
        String refreshToken = createRefreshToken(user);

        return new AuthResponse(token, refreshToken, mapToDTO(user), jwtExpiration);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        String token = tokenProvider.generateToken(authentication, user);
        String refreshToken = createRefreshToken(user);

        return new AuthResponse(token, refreshToken, mapToDTO(user), jwtExpiration);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenStr) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired");
        }

        User user = refreshToken.getUser();
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getUsername(), null, null
        );

        String newToken = tokenProvider.generateToken(authentication);
        String newRefreshToken = createRefreshToken(user);

        refreshTokenRepository.delete(refreshToken);

        return new AuthResponse(newToken, newRefreshToken, mapToDTO(user), jwtExpiration);
    }

    private String createRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(LocalDateTime.now().plusSeconds(refreshExpiration / 1000));

        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }

    /**
     * Assign a role to a user by inserting into user_roles table
     */
    private void assignRoleToUser(Long userId, String roleName) {
        entityManager.createNativeQuery(
            "INSERT INTO auth_service.user_roles (user_id, role_id) " +
            "SELECT :userId, r.id FROM auth_service.roles r WHERE r.name = :roleName " +
            "ON CONFLICT DO NOTHING"
        )
        .setParameter("userId", userId)
        .setParameter("roleName", roleName)
        .executeUpdate();
    }
    
    /**
     * Load role names for a user from the database
     */
    private Set<String> loadUserRoles(Long userId) {
        @SuppressWarnings("unchecked")
        List<String> roleNames = entityManager.createNativeQuery(
            "SELECT r.name FROM auth_service.user_roles ur " +
            "JOIN auth_service.roles r ON ur.role_id = r.id " +
            "WHERE ur.user_id = :userId"
        )
        .setParameter("userId", userId)
        .getResultList();
        
        return new HashSet<>(roleNames);
    }

    private UserDTO mapToDTO(User user) {
        // Load roles from database
        Set<String> roles = loadUserRoles(user.getId());
        user.setRoles(roles);
        
        UserDTO dto = new UserDTO();
        dto.setId(user.getId().toString());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setRoles(roles);
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLogin(user.getLastLogin());
        return dto;
    }
}

// Made with Bob
