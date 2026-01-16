package com.ibm.aimonitoring.auth.repository;

import com.ibm.aimonitoring.auth.model.RefreshToken;
import com.ibm.aimonitoring.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
}

// Made with Bob
