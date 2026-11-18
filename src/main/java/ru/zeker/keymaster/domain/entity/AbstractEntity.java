package ru.zeker.keymaster.domain.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;

@Getter
@Setter
@MappedSuperclass
public abstract class AbstractEntity extends PanacheEntityBase {

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;

        Class<?> oClass = o instanceof HibernateProxy p
                ? p.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisClass = this instanceof HibernateProxy p
                ? p.getHibernateLazyInitializer().getPersistentClass() : getClass();

        if (thisClass != oClass) return false;

        AbstractEntity that = (AbstractEntity) o;
        return getId() != null && Objects.equals(getId(), that.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy p
                ? p.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }

    protected abstract Object getId();
}
