package sk.janobono.api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.repository.AuthorityRepository;

@Service
public class AuthorityApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorityApiService.class);

    private AuthorityRepository authorityRepository;

    @Autowired
    public void setAuthorityRepository(AuthorityRepository authorityRepository) {
        this.authorityRepository = authorityRepository;
    }

    public Page<AuthoritySO> getAuthorities(Pageable pageable) {
        LOGGER.debug("getAuthorities({})", pageable);
        return authorityRepository.findAll(pageable).map(this::toAuthoritySO);
    }

    public AuthoritySO getAuthority(Long id) {
        LOGGER.debug("getAuthority({})", id);
        return authorityRepository.findById(id)
                .map(this::toAuthoritySO)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authority not found."));
    }

    @Transactional
    public AuthoritySO addAuthority(String authorityName) {
        LOGGER.debug("addAuthority({})", authorityName);
        if (authorityRepository.existsByName(authorityName)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authority exists.");
        }
        Authority authority = new Authority();
        authority.setName(authorityName);
        authority = authorityRepository.save(authority);
        AuthoritySO result = toAuthoritySO(authority);
        LOGGER.debug("addAuthority({})={}", authorityName, result);
        return result;
    }

    @Transactional
    public AuthoritySO setAuthority(Long id, String authorityName) {
        LOGGER.debug("setAuthority({},{})", id, authorityName);
        Authority authority = authorityRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authority not found."));
        authority.setName(authorityName);
        authority = authorityRepository.save(authority);
        AuthoritySO result = toAuthoritySO(authority);
        LOGGER.debug("setAuthority({})={}", authorityName, result);
        return result;
    }

    @Transactional
    public void deleteAuthority(Long id) {
        LOGGER.debug("deleteAuthority({})", id);
        if (!authorityRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authority not found.");
        }
        authorityRepository.deleteById(id);
    }

    private AuthoritySO toAuthoritySO(Authority authority) {
        return new AuthoritySO(authority.getId(), authority.getName());
    }
}
