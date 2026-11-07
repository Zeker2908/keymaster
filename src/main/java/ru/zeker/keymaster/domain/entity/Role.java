package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "role")
public class Role extends BaseEntity {

    public static final String ROLE_UQ = "role_name_uq";

    @Column(nullable = false, unique = true, length = 64)
    private String name;

    private String description;
}
