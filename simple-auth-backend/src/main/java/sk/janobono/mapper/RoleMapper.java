package sk.janobono.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Mappings;
import org.mapstruct.NullValueCheckStrategy;
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.dal.domain.Role;

@Mapper(nullValueCheckStrategy = NullValueCheckStrategy.ALWAYS)
public interface RoleMapper {

    Role roleDetailSOToRole(RoleDetailSO roleDetailSO);

    RoleDetailSO roleToRoleDetailSO(Role role);

    RoleSO roleToRoleSO(Role role);

    @Mappings({
            @Mapping(target = "id", ignore = true)
    })
    Role roleSOToRole(RoleSO roleSO);
}
