package com.example.demo.model;

import jakarta.persistence.*;

import java.util.Collection;
import java.util.Set;

@Entity
@Table(name="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column (name = "username",unique = true)
    private String username;
    @Column (name = "password",unique = true)
    private String password;
    @Column (name = "age")
    private int age;
    @ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.PERSIST, CascadeType.MERGE, CascadeType.DETACH, CascadeType.REFRESH })
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Collection<Role> roles;

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Collection<Role> getRoles() {
        return roles;
    }

    public User() {
    }

    public User(int age, String password, String username) {
        this.age = age;
        this.password = password;
        this.username = username;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setName(String name) {
        this.username = name;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getAge() {
        return age;
    }

    public String getPassword() {
        return password;
    }

    public String getName() {
        return username;
    }

    public Long getId() {
        return id;
    }
}