package sk.janobono.dal.domain;

import javax.persistence.*;
import java.util.*;

@Entity
@Table(name = "simple_auth_user")
@SequenceGenerator(name = "user_generator", allocationSize = 1, sequenceName = "sq_simple_auth_user")
public class User {

    @Id
    @Column(name = "id")
    @GeneratedValue(generator = "user_generator")
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "enabled")
    private Boolean enabled;

    @OneToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "simple_auth_user_authority",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id")
    )
    private List<Authority> authorities;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "simple_auth_user_attribute", joinColumns = @JoinColumn(name = "user_id"))
    @MapKeyColumn(name = "key")
    @Column(name = "value")
    private Map<String, String> attributes;

    @PrePersist
    @PreUpdate
    public void updateUsername() {
        this.username = username.toLowerCase();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public List<Authority> getAuthorities() {
        if (Objects.isNull(authorities)) {
            authorities = new ArrayList<>();
        }
        return authorities;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }

    public Map<String, String> getAttributes() {
        if (Objects.isNull(attributes)) {
            attributes = new HashMap<>();
        }
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", enabled=" + enabled +
                ", authorities=" + authorities +
                ", attributes=" + attributes +
                '}';
    }
}
