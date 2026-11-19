package com.example.rbac;

import com.example.rbac.entity.*;
import com.example.rbac.repository.*;
import com.example.rbac.security.CustomPermissionEvaluator;
import com.example.rbac.security.CustomUserDetailsService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class RbacTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository userRepo;

    @Autowired
    private RoleRepository roleRepo;

    @Autowired
    private PermissionRepository permissionRepo;

    @Autowired
    private CustomPermissionEvaluator evaluator;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Test
    void noLoginGives401() throws Exception {
        mockMvc.perform(get("/secure-data")).andExpect(status().isUnauthorized());
    }

    @Test
    void wrongPasswordGives401() throws Exception {
        mockMvc.perform(get("/secure-data").with(httpBasic("john", "wrong")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void userWithPermissionGets200() throws Exception {
        mockMvc.perform(get("/secure-data").with(httpBasic("john", "user123")))
                .andExpect(status().isOk());
    }

    @Test
    void adminWithoutPermissionGets403() throws Exception {
        mockMvc.perform(get("/secure-data").with(httpBasic("admin", "admin123")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCreatesRole() throws Exception {
        mockMvc.perform(post("/roles").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"MANAGER\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void userCannotCreateRole() throws Exception {
        mockMvc.perform(post("/roles").with(httpBasic("john", "user123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"MANAGER\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void duplicateRoleGives409() throws Exception {
        mockMvc.perform(post("/roles").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"ADMIN\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void blankRoleNameGives400() throws Exception {
        mockMvc.perform(post("/roles").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void adminCreatesPermission() throws Exception {
        mockMvc.perform(post("/permissions").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"REPORT_VIEW\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void duplicatePermissionGives409() throws Exception {
        mockMvc.perform(post("/permissions").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"SECURE_DATA_READ\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void blankPermissionNameGives400() throws Exception {
        mockMvc.perform(post("/permissions").with(httpBasic("admin", "admin123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void userCannotCreatePermission() throws Exception {
        mockMvc.perform(post("/permissions").with(httpBasic("john", "user123"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"X\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminAssignsPermissionToRole() throws Exception {
        Role role = roleRepo.save(new Role("TEST_ROLE"));
        Permission permission = permissionRepo.save(new Permission("TEST_PERMISSION"));
        String url = "/roles/" + role.getId() + "/permissions/" + permission.getId();

        mockMvc.perform(post(url).with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk());
        mockMvc.perform(post(url).with(httpBasic("admin", "admin123")))
                .andExpect(status().isConflict());
    }

    @Test
    void assignPermissionUnknownIdsGives404() throws Exception {
        mockMvc.perform(post("/roles/9999/permissions/9999").with(httpBasic("admin", "admin123")))
                .andExpect(status().isNotFound());
    }

    @Test
    void userCannotAssignPermission() throws Exception {
        mockMvc.perform(post("/roles/1/permissions/1").with(httpBasic("john", "user123")))
                .andExpect(status().isForbidden());
    }

    @Test
    void assigningRoleChangesAccess() throws Exception {
        AppUser alice = userRepo.save(new AppUser("alice", "{noop}alice123"));
        Role userRole = roleRepo.findByName("USER").orElseThrow();

        mockMvc.perform(get("/secure-data").with(httpBasic("alice", "alice123")))
                .andExpect(status().isForbidden());

        String url = "/users/" + alice.getId() + "/roles/" + userRole.getId();
        mockMvc.perform(post(url).with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/secure-data").with(httpBasic("alice", "alice123")))
                .andExpect(status().isOk());

        mockMvc.perform(post(url).with(httpBasic("admin", "admin123")))
                .andExpect(status().isConflict());
    }

    @Test
    void assignRoleUnknownIdsGives404() throws Exception {
        mockMvc.perform(post("/users/9999/roles/9999").with(httpBasic("admin", "admin123")))
                .andExpect(status().isNotFound());
    }

    @Test
    void userCannotAssignRole() throws Exception {
        mockMvc.perform(post("/users/1/roles/1").with(httpBasic("john", "user123")))
                .andExpect(status().isForbidden());
    }

    @Test
    void evaluatorReturnsFalseForNullValues() {
        var auth = new UsernamePasswordAuthenticationToken("john", "x", new ArrayList<>());
        assertFalse(evaluator.hasPermission(null, "ROLE", "CREATE"));
        assertFalse(evaluator.hasPermission(auth, null, "CREATE"));
        assertFalse(evaluator.hasPermission(auth, "ROLE", null));
    }

    @Test
    void evaluatorFourArgumentVersionWorks() {
        var auth = new UsernamePasswordAuthenticationToken("john", "x", new ArrayList<>());
        assertTrue(evaluator.hasPermission(auth, 1L, "SECURE_DATA", "READ"));
        assertFalse(evaluator.hasPermission(auth, 1L, "ROLE", "CREATE"));
    }

    @Test
    void unknownUserThrowsException() {
        assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername("ghost"));
    }
}
