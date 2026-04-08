package com.ibm.aimonitoring.auth.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "roles", schema = "auth_service")
@Data
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;
}
