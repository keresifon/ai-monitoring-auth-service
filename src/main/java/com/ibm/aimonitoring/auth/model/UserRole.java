package com.ibm.aimonitoring.auth.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "user_roles", schema = "auth_service")
@IdClass(UserRoleId.class)
@Data
public class UserRole {
    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "role_id")
    private Long roleId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", insertable = false, updatable = false)
    private Role role;
}
