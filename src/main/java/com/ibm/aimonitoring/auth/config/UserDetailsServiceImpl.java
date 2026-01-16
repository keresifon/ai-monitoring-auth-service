package com.ibm.aimonitoring.auth.config;

import com.ibm.aimonitoring.auth.model.User;
import com.ibm.aimonitoring.auth.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    
    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // Load roles from database
        @SuppressWarnings("unchecked")
        List<String> roleNames = entityManager.createNativeQuery(
            "SELECT r.name FROM auth_service.user_roles ur " +
            "JOIN auth_service.roles r ON ur.role_id = r.id " +
            "WHERE ur.user_id = :userId"
        )
        .setParameter("userId", user.getId())
        .getResultList();
        
        // If no roles, default to USER
        if (roleNames.isEmpty()) {
            roleNames = List.of("USER");
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(roleNames.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList()))
                .build();
    }
}

// Made with Bob
