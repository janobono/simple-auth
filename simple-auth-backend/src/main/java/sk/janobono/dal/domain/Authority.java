package sk.janobono.dal.domain;

import javax.persistence.*;
import java.util.Objects;

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

    public Authority() {
    }

    public Authority(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    @PrePersist
    @PreUpdate
    public void updateName() {
        this.name = name.toLowerCase();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Authority authority = (Authority) o;
        return Objects.equals(id, authority.id);
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "Authority{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
