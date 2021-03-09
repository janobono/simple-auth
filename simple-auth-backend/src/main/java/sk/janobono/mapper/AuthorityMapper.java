package sk.janobono.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.NullValueCheckStrategy;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.dal.domain.Authority;

@Mapper(nullValueCheckStrategy = NullValueCheckStrategy.ALWAYS)
public interface AuthorityMapper {

    AuthoritySO authorityToAuthoritySO(Authority authority);
}
