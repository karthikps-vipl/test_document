--
-- PostgreSQL database dump
-- Database: user_management_db
-- Purpose: Centralized user management and credential validation.
--
-- Architecture notes:
--   * This database validates user credentials and application access.
--   * Individual applications generate/manage their own JWTs and roles.
--   * Passwords must be stored as BCrypt/Argon2 hashes, never plaintext.
--   * Each registered application must have its own client credentials.
--
-- Restore:
--   1. Create the database:
--        CREATE DATABASE user_management_db;
--   2. Connect to it:
--        \c user_management_db
--   3. Execute this file:
--        psql -U <username> -d user_management_db -f user_management_db.sql
--
-- This script is intended for a new/empty database.
--

BEGIN;

-- ---------------------------------------------------------------------
-- 1. MASTER TABLES
-- ---------------------------------------------------------------------

CREATE TABLE rank_master (
    rank_id BIGSERIAL PRIMARY KEY,
    rank_code VARCHAR(30) UNIQUE,
    rank_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE macro_node_master (
    macro_node_id BIGSERIAL PRIMARY KEY,
    macro_node_code VARCHAR(50) UNIQUE,
    macro_node_name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE group_level_master (
    group_level_id BIGSERIAL PRIMARY KEY,
    group_level_code VARCHAR(50) UNIQUE,
    group_level_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE group_node_master (
    group_node_id BIGSERIAL PRIMARY KEY,
    macro_node_id BIGINT NOT NULL,
    group_node_code VARCHAR(50),
    group_node_name VARCHAR(150) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,

    CONSTRAINT fk_group_node_macro
        FOREIGN KEY (macro_node_id)
        REFERENCES macro_node_master(macro_node_id),

    CONSTRAINT uq_group_node_code
        UNIQUE (macro_node_id, group_node_code),

    CONSTRAINT uq_group_node_id_macro
        UNIQUE (group_node_id, macro_node_id)
);

CREATE TABLE user_type_master (
    user_type_id BIGSERIAL PRIMARY KEY,
    user_type_code VARCHAR(50) UNIQUE,
    user_type_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 2. APPLICATION MASTER
-- ---------------------------------------------------------------------
-- client_secret_hash must contain a securely generated password hash.
-- Do not store the application's raw client secret in this column.
-- Store the raw secret securely in the application configuration/secret
-- manager and compare it securely in the authentication service.

CREATE TABLE application_master (
    application_id BIGSERIAL PRIMARY KEY,
    application_code VARCHAR(50) NOT NULL UNIQUE,
    application_name VARCHAR(150) NOT NULL,
    application_url VARCHAR(255),

    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,

    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 3. USERS
-- ---------------------------------------------------------------------
-- password_hash must contain a BCrypt/Argon2 hash.
-- Username uniqueness is enforced case-insensitively by the index below.
-- Group Node is constrained to belong to the selected Macro Node.

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,

    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    rank_id BIGINT,
    email_address VARCHAR(150),
    macro_node_id BIGINT,
    phone_number VARCHAR(20),

    group_level_id BIGINT,
    group_node_id BIGINT,

    user_type_id BIGINT,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    account_locked_until TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,

    CONSTRAINT fk_user_rank
        FOREIGN KEY (rank_id)
        REFERENCES rank_master(rank_id),

    CONSTRAINT fk_user_macro_node
        FOREIGN KEY (macro_node_id)
        REFERENCES macro_node_master(macro_node_id),

    CONSTRAINT fk_user_group_level
        FOREIGN KEY (group_level_id)
        REFERENCES group_level_master(group_level_id),

    CONSTRAINT fk_user_group_node
        FOREIGN KEY (group_node_id, macro_node_id)
        REFERENCES group_node_master(group_node_id, macro_node_id),

    CONSTRAINT fk_user_type
        FOREIGN KEY (user_type_id)
        REFERENCES user_type_master(user_type_id),

    CONSTRAINT chk_failed_attempts
        CHECK (failed_login_attempts >= 0)
);

CREATE UNIQUE INDEX uq_users_username_lower
    ON users (LOWER(username));

CREATE INDEX idx_users_macro_node
    ON users (macro_node_id);

CREATE INDEX idx_users_group_level
    ON users (group_level_id);

CREATE INDEX idx_users_group_node
    ON users (group_node_id);

-- ---------------------------------------------------------------------
-- 4. USER-APPLICATION ACCESS MAPPING
-- ---------------------------------------------------------------------
-- This table only controls whether a user may authenticate to an
-- application. Application roles/permissions remain in each application.

CREATE TABLE user_application_mapping (
    mapping_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL,
    application_id BIGINT NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by BIGINT,

    CONSTRAINT fk_mapping_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id),

    CONSTRAINT fk_mapping_application
        FOREIGN KEY (application_id)
        REFERENCES application_master(application_id),

    CONSTRAINT fk_mapping_assigned_by
        FOREIGN KEY (assigned_by)
        REFERENCES users(user_id),

    CONSTRAINT uq_user_application
        UNIQUE (user_id, application_id)
);

CREATE INDEX idx_user_application_user
    ON user_application_mapping(user_id);

CREATE INDEX idx_user_application_app
    ON user_application_mapping(application_id);

-- ---------------------------------------------------------------------
-- 5. LOGIN AUDIT
-- ---------------------------------------------------------------------
-- Never store submitted passwords or password hashes in this table.

CREATE TABLE login_audit (
    audit_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT,
    application_id BIGINT,

    username VARCHAR(100) NOT NULL,

    login_status VARCHAR(20) NOT NULL,
    failure_reason VARCHAR(255),

    ip_address INET,
    user_agent TEXT,

    login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL,

    CONSTRAINT fk_audit_application
        FOREIGN KEY (application_id)
        REFERENCES application_master(application_id)
        ON DELETE SET NULL,

    CONSTRAINT chk_login_status
        CHECK (login_status IN ('SUCCESS', 'FAILED', 'BLOCKED'))
);

CREATE INDEX idx_login_audit_user
    ON login_audit(user_id);

CREATE INDEX idx_login_audit_time
    ON login_audit(login_time);

CREATE INDEX idx_login_audit_username
    ON login_audit(username);

-- ---------------------------------------------------------------------
-- 6. UPDATED_AT TRIGGER FUNCTION AND TRIGGERS
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_modified_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_rank_updated
BEFORE UPDATE ON rank_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_macro_node_updated
BEFORE UPDATE ON macro_node_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_group_level_updated
BEFORE UPDATE ON group_level_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_group_node_updated
BEFORE UPDATE ON group_node_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_user_type_updated
BEFORE UPDATE ON user_type_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

CREATE TRIGGER trg_application_updated
BEFORE UPDATE ON application_master
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

-- ---------------------------------------------------------------------
-- 7. SAMPLE MASTER DATA
-- ---------------------------------------------------------------------
-- Replace these illustrative records with your actual organizational
-- ranks, macro nodes, group levels, group nodes, user types and apps.

INSERT INTO rank_master (rank_code, rank_name)
VALUES
    ('R001', 'Manager'),
    ('R002', 'Senior Manager'),
    ('R003', 'Engineer'),
    ('R004', 'Administrator');

INSERT INTO macro_node_master (macro_node_code, macro_node_name)
VALUES
    ('MN001', 'Bangalore'),
    ('MN002', 'Mumbai'),
    ('MN003', 'Hyderabad');

INSERT INTO group_level_master (group_level_code, group_level_name)
VALUES
    ('GL001', 'Level 1'),
    ('GL002', 'Level 2'),
    ('GL003', 'Level 3');

INSERT INTO group_node_master
    (macro_node_id, group_node_code, group_node_name)
VALUES
    (1, 'GN001', 'Bangalore North'),
    (1, 'GN002', 'Bangalore South'),
    (2, 'GN003', 'Mumbai Central'),
    (2, 'GN004', 'Mumbai East');

INSERT INTO user_type_master (user_type_code, user_type_name)
VALUES
    ('UT001', 'Internal'),
    ('UT002', 'External'),
    ('UT003', 'Guest');

-- The following application rows are examples only.
-- Replace the placeholder hashes with real hashes before enabling
-- application authentication. Never use '<bcrypt-hash>' in production.
INSERT INTO application_master
    (application_code, application_name, application_url,
     client_id, client_secret_hash, description)
VALUES
    ('NMS', 'Network Management System',
     'https://nms.company.com', 'nms-client',
     '<REPLACE_WITH_REAL_CLIENT_SECRET_HASH>',
     'Network Management System'),

    ('CNMS', 'Core Network Management System',
     'https://cnms.company.com', 'cnms-client',
     '<REPLACE_WITH_REAL_CLIENT_SECRET_HASH>',
     'Core Network Management System'),

    ('RNMS', 'Radio Network Management System',
     'https://rnms.company.com', 'rnms-client',
     '<REPLACE_WITH_REAL_CLIENT_SECRET_HASH>',
     'Radio Network Management System');

COMMIT;

-- ---------------------------------------------------------------------
-- 8. USEFUL LOOKUP QUERIES
-- ---------------------------------------------------------------------

-- Active ranks:
-- SELECT rank_id, rank_name
-- FROM rank_master
-- WHERE is_active = TRUE
-- ORDER BY rank_name;

-- Active macro nodes:
-- SELECT macro_node_id, macro_node_name
-- FROM macro_node_master
-- WHERE is_active = TRUE
-- ORDER BY macro_node_name;

-- Group nodes for a selected macro node:
-- SELECT group_node_id, group_node_name
-- FROM group_node_master
-- WHERE macro_node_id = 1
--   AND is_active = TRUE
-- ORDER BY group_node_name;

-- Active user types:
-- SELECT user_type_id, user_type_name
-- FROM user_type_master
-- WHERE is_active = TRUE
-- ORDER BY user_type_name;

-- Validate that a user exists, is active, is not currently locked,
-- and has access to the requested active application.
-- The application service must separately verify the supplied password
-- against password_hash using BCrypt/Argon2.
--
-- SELECT
--     u.user_id,
--     u.username,
--     u.password_hash,
--     u.email_address,
--     u.rank_id,
--     u.macro_node_id,
--     u.phone_number,
--     u.group_level_id,
--     u.group_node_id,
--     u.user_type_id,
--     a.application_id,
--     a.application_code
-- FROM users u
-- JOIN user_application_mapping uam
--     ON u.user_id = uam.user_id
-- JOIN application_master a
--     ON uam.application_id = a.application_id
-- WHERE LOWER(u.username) = LOWER(:username)
--   AND a.application_code = :applicationCode
--   AND u.is_active = TRUE
--   AND uam.is_active = TRUE
--   AND a.is_active = TRUE
--   AND (
--       u.account_locked_until IS NULL
--       OR u.account_locked_until <= CURRENT_TIMESTAMP
--   );
--
-- End of schema dump.









1. Authentication APIs
These APIs will be consumed by NMS, CNMS, RNMS and other applications.
Method	API				Purpose
POST	/api/auth/validate	        Validate username, password and application access
POST	/api/auth/change-password	Change user password
POST	/api/auth/forgot-password	Initiate password reset
POST	/api/auth/reset-password	Reset password using a valid reset token

2. User Management APIs
These APIs will be used by the central User Management frontend.
Method	API			Purpose
POST	/api/users	Create a new user
GET	/api/users	Get all users
GET	/api/users/{userId}	Get user details
PUT	/api/users/{userId}	Update user details
PATCH	/api/users/{userId}/status	Activate/deactivate user
DELETE	/api/users/{userId}	Delete user (prefer soft deletion)
PUT	/api/users/{userId}/password	Reset/change user password
GET	/api/users/{userId}/applications	Get applications assigned to user
PUT	/api/users/{userId}/applications	Assign/update application access



3. Master Data APIs
These APIs populate dropdowns in the User Management frontend.
Method	API	Purpose
GET	/api/master/ranks	Get all active ranks
POST	/api/master/ranks	Add rank
PUT	/api/master/ranks/{id}	Update rank
PATCH	/api/master/ranks/{id}/status	Activate/deactivate rank
GET	/api/master/macro-nodes	Get all active macro nodes
POST	/api/master/macro-nodes	Add macro node
PUT	/api/master/macro-nodes/{id}	Update macro node
PATCH	/api/master/macro-nodes/{id}/status	Activate/deactivate macro node
GET	/api/master/group-levels	Get group levels
POST	/api/master/group-levels	Add group level
PUT	/api/master/group-levels/{id}	Update group level
PATCH	/api/master/group-levels/{id}/status	Activate/deactivate group level
GET	/api/master/group-nodes/{macroNodeId}	Get group nodes by macro node
POST	/api/master/group-nodes	Add group node
PUT	/api/master/group-nodes/{id}	Update group node
PATCH	/api/master/group-nodes/{id}/status	Activate/deactivate group node
GET	/api/master/user-types	Get user types
POST	/api/master/user-types	Add user type
PUT	/api/master/user-types/{id}	Update user type
PATCH	/api/master/user-types/{id}/status	Activate/deactivate user type




4. Application Management APIs
These APIs manage applications registered with the central authentication service.
Method	API	Purpose
POST	/api/applications	Register a new application
GET	/api/applications	Get all applications
GET	/api/applications/{applicationId}	Get application details
PUT	/api/applications/{applicationId}	Update application details
PATCH	/api/applications/{applicationId}/status	Activate/deactivate application
POST	/api/applications/{applicationId}/regenerate-secret	Regenerate application client secret


6. Login Audit APIs
These APIs allow the administrator to monitor login activity.
Method	API	Purpose
GET	/api/audit/logins	Get login history
GET	/api/audit/logins/{userId}	Get login history for a particular user
GET	/api/audit/failed-logins	Get failed login attempts
GET	/api/audit/logins/application/{applicationId}	Get login history by application


7. Recommended Additional APIs
These are useful for administration and operational management.
Method	API	Purpose
GET	/api/dashboard/summary	Dashboard statistics
GET	/api/users/search	Search users by username, email or phone
GET	/api/users/locked	Get locked user accounts
PATCH	/api/users/{userId}/unlock	Unlock user account
GET	/api/applications/active	Get active applications
GET	/api/users/{userId}/profile	Get user profile






