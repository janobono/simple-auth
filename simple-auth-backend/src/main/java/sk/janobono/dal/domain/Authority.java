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
@Table(name = "simple_auth_authority")
@SequenceGenerator(name = "authority_generator", allocationSize = 1, sequenceName = "sq_simple_auth_authority")
public class Authority {

    @Id
    @Column(name = "id")
    @GeneratedValue(generator = "authority_generator")
    private Long id;

    @Column(name = "name")
    private String name;

    @PrePersist
    @PreUpdate
    public void updateName() {
        this.name = name.toLowerCase();
    }
}
