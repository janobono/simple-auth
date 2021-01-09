package sk.janobono.dal.domain;

import lombok.*;

import javax.persistence.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(of = "id")
@ToString
@Entity
@Table(name = "simple_auth_role")
@SequenceGenerator(name = "role_generator", allocationSize = 1, sequenceName = "sq_simple_auth_role")
public class Role {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    @GeneratedValue(generator = "role_generator")
    private Long id;

    @Column(name = "name", nullable = false, unique = true)
    private String name;

    @PrePersist
    @PreUpdate
    public void updateName() {
        this.name = name.toLowerCase();
    }
}
