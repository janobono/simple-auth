package sk.janobono.mapper;

import org.mapstruct.BeforeMapping;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValueCheckStrategy;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import java.util.Comparator;

@Mapper(nullValueCheckStrategy = NullValueCheckStrategy.ALWAYS, uses = {AuthorityMapper.class})
public interface UserMapper {

    UserSO userToUserSO(User user);

    @BeforeMapping
    static void userToUserSO(User user, @MappingTarget UserSO userSO) {
        user.getAuthorities().sort(Comparator.comparing(Authority::getId));
    }
}
