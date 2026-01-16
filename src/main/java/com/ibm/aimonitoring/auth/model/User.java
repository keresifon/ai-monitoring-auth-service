package com.ibm.aimonitoring.auth.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", schema = "auth_service")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String password;

    private String firstName;
    private String lastName;

    // Roles are stored in user_roles table with role_id (integer FK to roles table)
    // This is a transient field - roles are loaded/assigned via service layer
    @Transient
    private Set<String> roles = new HashSet<>();

    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        // Roles are handled in service layer, not here
    }
}

// Made with Bob
