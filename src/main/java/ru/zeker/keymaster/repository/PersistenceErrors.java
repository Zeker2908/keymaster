package ru.zeker.keymaster.repository;

import io.smallrye.mutiny.Uni;
import ru.zeker.keymaster.util.ExceptionTranslator;

/**
 * Translates database constraint failures into domain exceptions at the repository boundary.
 * Services should not know about SQL states or constraint names.
 */
public final class PersistenceErrors {

    private PersistenceErrors() {
    }

    public static <T> Uni<T> translate(Uni<T> source) {
        return source.onFailure().transform(ExceptionTranslator::translate);
    }
}
