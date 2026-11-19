package com.example.rbac.config;

import com.example.rbac.entity.*;
import com.example.rbac.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final AppUserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PermissionRepository permissionRepo;
    private final RolePermissionRepository rolePermissionRepo;
    private final UserRoleRepository userRoleRepo;

    public DataInitializer(AppUserRepository userRepo, RoleRepository roleRepo,
                           PermissionRepository permissionRepo,
                           RolePermissionRepository rolePermissionRepo,
                           UserRoleRepository userRoleRepo) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.permissionRepo = permissionRepo;
        this.rolePermissionRepo = rolePermissionRepo;
        this.userRoleRepo = userRoleRepo;
    }

    @Override
    public void run(String... args) {
        if (roleRepo.count() > 0) {
            return;
        }

        Role admin = roleRepo.save(new Role("ADMIN"));
        Role user = roleRepo.save(new Role("USER"));

        Permission roleCreate = permissionRepo.save(new Permission("ROLE_CREATE"));
        Permission permissionCreate = permissionRepo.save(new Permission("PERMISSION_CREATE"));
        Permission rolePermissionAssign = permissionRepo.save(new Permission("ROLE_PERMISSION_ASSIGN"));
        Permission userRoleAssign = permissionRepo.save(new Permission("USER_ROLE_ASSIGN"));
        Permission secureDataRead = permissionRepo.save(new Permission("SECURE_DATA_READ"));

        rolePermissionRepo.save(new RolePermission(admin.getId(), roleCreate.getId()));
        rolePermissionRepo.save(new RolePermission(admin.getId(), permissionCreate.getId()));
        rolePermissionRepo.save(new RolePermission(admin.getId(), rolePermissionAssign.getId()));
        rolePermissionRepo.save(new RolePermission(admin.getId(), userRoleAssign.getId()));
        rolePermissionRepo.save(new RolePermission(user.getId(), secureDataRead.getId()));

        AppUser adminUser = userRepo.save(new AppUser("admin", "{noop}admin123"));
        AppUser normalUser = userRepo.save(new AppUser("john", "{noop}user123"));

        userRoleRepo.save(new UserRole(adminUser.getId(), admin.getId()));
        userRoleRepo.save(new UserRole(normalUser.getId(), user.getId()));
    }
}
