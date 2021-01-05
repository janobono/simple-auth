package sk.janobono;

import io.github.benas.randombeans.EnhancedRandomBuilder;
import io.github.benas.randombeans.FieldPredicates;
import io.github.benas.randombeans.api.EnhancedRandom;
import io.github.benas.randombeans.randomizers.EmailRandomizer;

public class TestEnhancedRandomBuilder {

    public static EnhancedRandom build() {
        return EnhancedRandomBuilder.aNewEnhancedRandomBuilder()
                .randomize(FieldPredicates.named("email").and(FieldPredicates.ofType(String.class)), new EmailRandomizer())
                .build();
    }
}
