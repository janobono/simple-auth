package sk.janobono.dal.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.*;
import java.util.stream.Collectors;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(of = {"id"})
@ToString(exclude = {"password"})
@Entity
@Table(name = "simple_auth_user")
@SequenceGenerator(name = "user_generator", allocationSize = 1, sequenceName = "sq_simple_auth_user")
public class User implements UserDetails {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(generator = "user_generator")
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.MERGE)
    @JoinTable(name = "simple_auth_user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "simple_auth_user_attribute",
            joinColumns = @JoinColumn(name = "user_id"),
            uniqueConstraints = {
                    @UniqueConstraint(columnNames = {"user_id", "key"})
            })
    @MapKeyColumn(name = "key")
    @Column(name = "value")
    private Map<String, String> attributes;

    public Set<Role> getRoles() {
        if (roles == null) {
            roles = new HashSet<>();
        }
        return roles;
    }

    public Map<String, String> getAttributes() {
        if (attributes == null) {
            attributes = new HashMap<>();
        }
        return attributes;
    }

    @PrePersist
    @PreUpdate
    public void updateUsername() {
        this.username = username.toLowerCase();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getRoles().stream().map(r -> {
            String roleName = r.getName();
            if (!roleName.startsWith("ROLE_")) {
                roleName = "ROLE_" + roleName;
            }
            return new SimpleGrantedAuthority(roleName);
        }).collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
