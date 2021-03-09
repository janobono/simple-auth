package sk.janobono.dal.domain;

import lombok.*;

import javax.persistence.*;
import java.util.*;

@Getter
@Setter
@EqualsAndHashCode(of = "id")
@ToString(exclude = "password")
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

    public List<Authority> getAuthorities() {
        if (Objects.isNull(authorities)) {
            authorities = new ArrayList<>();
        }
        return authorities;
    }

    public Map<String, String> getAttributes() {
        if (Objects.isNull(attributes)) {
            attributes = new HashMap<>();
        }
        return attributes;
    }

    @PrePersist
    @PreUpdate
    public void updateUsername() {
        this.username = username.toLowerCase();
    }
}
