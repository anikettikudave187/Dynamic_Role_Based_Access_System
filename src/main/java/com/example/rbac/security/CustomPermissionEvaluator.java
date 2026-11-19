package com.example.rbac.security;

import com.example.rbac.repository.RolePermissionRepository;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final RolePermissionRepository rolePermissionRepository;

    public CustomPermissionEvaluator(RolePermissionRepository rolePermissionRepository) {
        this.rolePermissionRepository = rolePermissionRepository;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        if (authentication == null || target == null || permission == null) {
            return false;
        }
        String permissionName = target + "_" + permission;
        long count = rolePermissionRepository.countUserPermission(authentication.getName(), permissionName);
        return count > 0;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permission) {
        return hasPermission(authentication, targetType, permission);
    }
}
