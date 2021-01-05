package sk.janobono.mapper;

import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.NullValueCheckStrategy;

@Mapper(nullValueCheckStrategy = NullValueCheckStrategy.ALWAYS, uses = {RoleMapper.class})
public interface UserMapper {

    UserDetailSO userToUserDetailSO(User user);

    UserSO userToUserSO(User user);

    @Mappings({
            @Mapping(target = "id", ignore = true)
    })
    User userSOToUser(UserSO userSO);
}
