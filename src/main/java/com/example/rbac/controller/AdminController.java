package com.example.rbac.controller;

import com.example.rbac.entity.*;
import com.example.rbac.repository.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
public class AdminController {

    private final AppUserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PermissionRepository permissionRepo;
    private final RolePermissionRepository rolePermissionRepo;
    private final UserRoleRepository userRoleRepo;

    public AdminController(AppUserRepository userRepo, RoleRepository roleRepo,
                           PermissionRepository permissionRepo,
                           RolePermissionRepository rolePermissionRepo,
                           UserRoleRepository userRoleRepo) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.permissionRepo = permissionRepo;
        this.rolePermissionRepo = rolePermissionRepo;
        this.userRoleRepo = userRoleRepo;
    }

    @PostMapping("/roles")
    @PreAuthorize("hasPermission('ROLE', 'CREATE')")
    @ResponseStatus(HttpStatus.CREATED)
    public Role createRole(@RequestBody Map<String, String> body) {
        String name = body.get("name");
        if (name == null || name.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name is required");
        }
        if (roleRepo.findByName(name).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Role already exists");
        }
        return roleRepo.save(new Role(name));
    }

    @PostMapping("/permissions")
    @PreAuthorize("hasPermission('PERMISSION', 'CREATE')")
    @ResponseStatus(HttpStatus.CREATED)
    public Permission createPermission(@RequestBody Map<String, String> body) {
        String name = body.get("name");
        if (name == null || name.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Name is required");
        }
        if (permissionRepo.findByName(name).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Permission already exists");
        }
        return permissionRepo.save(new Permission(name));
    }

    @PostMapping("/roles/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasPermission('ROLE_PERMISSION', 'ASSIGN')")
    public RolePermission assignPermissionToRole(@PathVariable Long roleId,
                                                 @PathVariable Long permissionId) {
        if (!roleRepo.existsById(roleId) || !permissionRepo.existsById(permissionId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Role or permission not found");
        }
        if (rolePermissionRepo.existsByRoleIdAndPermissionId(roleId, permissionId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Already assigned");
        }
        return rolePermissionRepo.save(new RolePermission(roleId, permissionId));
    }

    @PostMapping("/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasPermission('USER_ROLE', 'ASSIGN')")
    public UserRole assignRoleToUser(@PathVariable Long userId, @PathVariable Long roleId) {
        if (!userRepo.existsById(userId) || !roleRepo.existsById(roleId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User or role not found");
        }
        if (userRoleRepo.existsByUserIdAndRoleId(userId, roleId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Already assigned");
        }
        return userRoleRepo.save(new UserRole(userId, roleId));
    }
}
