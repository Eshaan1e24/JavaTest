package com.sit.campusbackend.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "admins")
@Data
public class Admin {

    @Id
    private String email;

    private String passwordHash;

    private String firstName;

    private String lastName;

    // Role is always ADMIN — no field needed, hardcoded in UserDetailsService
}
