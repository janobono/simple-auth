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
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.dal.domain.Role;
import sk.janobono.dal.repository.RoleRepository;
import sk.janobono.mapper.RoleMapper;

@Service
public class RoleApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleApiService.class);

    private RoleMapper roleMapper;

    private RoleRepository roleRepository;

    @Autowired
    public void setRoleMapper(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    @Autowired
    public void setRoleRepository(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Page<RoleDetailSO> getRoles(Pageable pageable) {
        LOGGER.debug("getRoles({})", pageable);
        return roleRepository.findAll(pageable).map(roleMapper::roleToRoleDetailSO);
    }

    public RoleDetailSO getRole(Long id) {
        LOGGER.debug("getRole({})", id);
        return roleRepository.findById(id)
                .map(roleMapper::roleToRoleDetailSO)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role not found!"));
    }

    @Transactional
    public RoleDetailSO addRole(RoleSO roleSO) {
        LOGGER.debug("addRole({})", roleSO);
        if (roleRepository.existsByName(roleSO.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role exists!");
        }
        Role role = roleRepository.save(roleMapper.roleSOToRole(roleSO));
        LOGGER.debug("addRole({})={}", roleSO, role);
        return roleMapper.roleToRoleDetailSO(role);
    }

    @Transactional
    public RoleDetailSO setRole(Long id, RoleSO roleSO) {
        LOGGER.debug("setRole({},{})", id, roleSO);
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role not found!"));
        role.setName(roleSO.getName());
        role = roleRepository.save(role);
        LOGGER.debug("setRole({})={}", roleSO, role);
        return roleMapper.roleToRoleDetailSO(role);
    }

    @Transactional
    public void deleteRole(Long id) {
        LOGGER.debug("deleteRole({})", id);
        if (!roleRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role not found!");
        }
        roleRepository.deleteById(id);
    }
}
