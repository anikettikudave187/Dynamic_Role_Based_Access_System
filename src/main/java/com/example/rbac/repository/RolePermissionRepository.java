package com.example.rbac.repository;

import com.example.rbac.entity.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RolePermissionRepository extends JpaRepository<RolePermission, Long> {

    boolean existsByRoleIdAndPermissionId(Long roleId, Long permissionId);

    @Query("select count(rp) from AppUser u, UserRole ur, RolePermission rp, Permission p "
            + "where u.username = :username "
            + "and ur.userId = u.id "
            + "and rp.roleId = ur.roleId "
            + "and p.id = rp.permissionId "
            + "and p.name = :permissionName")
    long countUserPermission(@Param("username") String username,
                             @Param("permissionName") String permissionName);
}
