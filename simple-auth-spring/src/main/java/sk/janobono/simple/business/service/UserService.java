package sk.janobono.simple.business.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.PageUser;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.api.model.UserCreate;
import sk.janobono.simple.api.model.UserProfile;
import sk.janobono.simple.business.model.UserSearchCriteriaData;
import sk.janobono.simple.common.component.ScDf;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.dal.domain.AuthorityDo;
import sk.janobono.simple.dal.domain.UserDo;
import sk.janobono.simple.dal.model.UserSearchCriteriaDo;
import sk.janobono.simple.dal.repository.AuthorityRepository;
import sk.janobono.simple.dal.repository.UserRepository;

@RequiredArgsConstructor
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final ScDf scDf;

    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;

    @Transactional
    public User addUser(final UserCreate userCreate) {
        if (userRepository.existsByEmail(scDf.toStripAndLowerCase(userCreate.getEmail()))) {
            throw SimpleAuthServiceException.USER_EMAIL_IS_USED.exception("Email is used");
        }

        final UserDo userDo = userRepository.save(
            UserDo.builder()
                .email(scDf.toStripAndLowerCase(userCreate.getEmail()))
                .password(passwordEncoder.encode(RandomStringUtils.secure().nextAlphanumeric(10)))
                .firstName(userCreate.getFirstName())
                .lastName(userCreate.getLastName())
                .confirmed(userCreate.getConfirmed())
                .enabled(userCreate.getEnabled())
                .authorities(toAuthorities(userCreate.getAuthorities()))
                .build()
        );

        return mapToUser(userDo);
    }

    @Transactional
    public void deleteUser(final Long id) {
        if (!userRepository.existsById(id)) {
            throw SimpleAuthServiceException.USER_NOT_FOUND.exception("User with id {0} not found", id);
        }
        userRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public User getUser(final Long id) {
        return mapToUser(userRepository.getUserDo(id));
    }

    @Transactional(readOnly = true)
    public PageUser getUsers(final UserSearchCriteriaData criteria, final Pageable pageable) {
        final Page<UserDo> data = userRepository.findAll(
            UserSearchCriteriaDo.builder()
                .searchField(Optional.ofNullable(criteria.searchField()).map(scDf::toScDf).orElse(null))
                .email(Optional.ofNullable(criteria.email()).map(scDf::toStripAndLowerCase).orElse(null))
                .build(), pageable);
        return PageUser.builder()
            .totalElements(data.getTotalElements())
            .totalPages(data.getTotalPages())
            .first(data.isFirst())
            .last(data.isLast())
            .page(data.getPageable().getPageSize())
            .size(data.getSize())
            .content(data.getContent().stream()
                .map(this::mapToUser)
                .toList())
            .empty(data.isEmpty())
            .build();
    }

    @Transactional
    public User setAuthorities(final Long id, final List<Authority> authorities) {
        final UserDo userDo = userRepository.getUserDo(id);

        userDo.setAuthorities(toAuthorities(authorities));

        return mapToUser(userRepository.save(userDo));
    }

    @Transactional
    public User setConfirmed(final Long id, final boolean confirmed) {
        final UserDo userDo = userRepository.getUserDo(id);

        userDo.setConfirmed(confirmed);

        return mapToUser(userRepository.save(userDo));
    }

    @Transactional
    public User setEnabled(final Long id, final boolean enabled) {
        final UserDo userDo = userRepository.getUserDo(id);

        userDo.setEnabled(enabled);

        return mapToUser(userRepository.save(userDo));
    }

    @Transactional
    public User setUser(final Long id, final UserProfile userProfile) {
        final UserDo userDo = userRepository.getUserDo(id);

        userDo.setFirstName(userProfile.getFirstName());
        userDo.setLastName(userProfile.getLastName());

        return mapToUser(userRepository.save(userDo));
    }

    private User mapToUser(final UserDo userDo) {
        return Optional.ofNullable(userDo)
            .map(data -> User.builder()
                .id(data.getId())
                .email(data.getEmail())
                .firstName(data.getFirstName())
                .lastName(data.getLastName())
                .confirmed(data.isConfirmed())
                .enabled(data.isEnabled())
                .authorities(data.getAuthorities().stream().map(AuthorityDo::getAuthority).collect(Collectors.toList()))
                .build()
            )
            .orElse(null);
    }

    private List<AuthorityDo> toAuthorities(final List<Authority> authorities) {
        if (Optional.ofNullable(authorities).isEmpty()) {
            return Collections.emptyList();
        }
        final List<AuthorityDo> result = new ArrayList<>();
        for (final Authority authority : authorities) {
            result.add(authorityRepository.findByAuthority(authority)
                .orElseThrow(() -> SimpleAuthServiceException.AUTHORITY_NOT_FOUND.exception("Authority {0} not found", authority))
            );
        }
        return result;
    }
}
