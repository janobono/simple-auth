package sk.janobono.component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import java.util.Comparator;
import java.util.stream.Collectors;

@Component
public class UserComponent {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserComponent.class);

    public UserSO toUserSO(User user) {
        LOGGER.debug("toUserSO({})", user);
        UserSO result = new UserSO(
                user.getId(),
                user.getUsername(),
                user.getEnabled(),
                user.getAuthorities().stream()
                        .sorted(Comparator.comparing(Authority::getId))
                        .map(a -> new AuthoritySO(a.getId(), a.getName()))
                        .collect(Collectors.toList()),
                user.getAttributes()
        );
        LOGGER.debug("toUserSO({})={}", user, result);
        return result;
    }
}
