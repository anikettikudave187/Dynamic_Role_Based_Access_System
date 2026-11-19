# Dynamic RBAC Authorization Engine

Spring Boot + Spring Security + H2. Roles, permissions and mappings are stored in the
database and checked at runtime with a custom PermissionEvaluator.

## How to run

Requirements: Java 17+ and Maven.

```bash
mvn clean verify
mvn spring-boot:run
```

App runs on http://localhost:8080. Data is saved in `./data/rbacdb.mv.db`.
Coverage report: `target/site/jacoco/index.html`

## Starter users (saved in the database on first start)

| Username | Password | Role  | Permissions |
|----------|----------|-------|-------------|
| admin    | admin123 | ADMIN | ROLE_CREATE, PERMISSION_CREATE, ROLE_PERMISSION_ASSIGN, USER_ROLE_ASSIGN |
| john     | user123  | USER  | SECURE_DATA_READ |

## Authorization flow

1. Client calls an API with username and password (HTTP Basic).
2. `CustomUserDetailsService` loads the user from the database.
3. The controller method has `@PreAuthorize("hasPermission('ROLE', 'CREATE')")`.
4. Spring calls `CustomPermissionEvaluator`.
5. The evaluator builds the permission name `ROLE_CREATE` and queries the database:
   user -> user_roles -> role_permissions -> permissions.
6. If a row is found the request is allowed, otherwise the response is 403 Forbidden.

## Permission evaluation logic

`hasPermission('TARGET', 'ACTION')` becomes the permission name `TARGET_ACTION`
and is looked up in the database on every request.
Example: `hasPermission('SECURE_DATA', 'READ')` checks `SECURE_DATA_READ`.

## How PermissionEvaluator is used

`CustomPermissionEvaluator` implements Spring's `PermissionEvaluator` interface.
`MethodSecurityConfig` registers it, so every `hasPermission(...)` inside `@PreAuthorize`
calls our class.

## Why hardcoded roles are avoided

With `hasRole('ADMIN')` the rules are written inside the code, so any change needs a code
change and redeploy. With database permissions, an admin changes access using the APIs
without restarting. Proof: `admin` gets 403 on `/secure-data` because the ADMIN role has
no `SECURE_DATA_READ` row in the database.

## Example permission checks

```java
@PreAuthorize("hasPermission('ROLE', 'CREATE')")
@PreAuthorize("hasPermission('PERMISSION', 'CREATE')")
@PreAuthorize("hasPermission('ROLE_PERMISSION', 'ASSIGN')")
@PreAuthorize("hasPermission('USER_ROLE', 'ASSIGN')")
@PreAuthorize("hasPermission('SECURE_DATA', 'READ')")
```

## Example API calls

```bash
curl -u admin:admin123 -X POST localhost:8080/roles -H "Content-Type: application/json" -d '{"name":"MANAGER"}'
curl -u admin:admin123 -X POST localhost:8080/permissions -H "Content-Type: application/json" -d '{"name":"REPORT_VIEW"}'
curl -u admin:admin123 -X POST localhost:8080/roles/3/permissions/6
curl -u admin:admin123 -X POST localhost:8080/users/2/roles/2
curl -u john:user123 localhost:8080/secure-data
```

## Note

Starter passwords use the `{noop}` prefix (plain text) to keep the demo simple.
A real project should store BCrypt hashes.
