#![allow(dead_code)]
use aegis_common::config::RolePermissions;
use std::collections::HashMap;

/// Role-Based Access Control engine.
///
/// Determines whether a given user role is permitted to perform
/// specific actions (authorize, block, configure, etc.).
pub struct RbacEngine {
    roles: HashMap<String, RolePermissions>,
}

impl RbacEngine {
    pub fn new(roles: HashMap<String, RolePermissions>) -> Self {
        Self { roles }
    }

    /// Check if a role is authorized for a specific action.
    pub fn check_permission(&self, role: &str, action: &str) -> bool {
        if let Some(perms) = self.roles.get(role) {
            match action {
                "authorize" => perms.can_authorize,
                "block" => perms.can_block,
                "view_logs" => perms.can_view_logs,
                "configure" => perms.can_configure,
                "eject" => perms.can_eject,
                _ => {
                    tracing::warn!(role, action, "Unknown RBAC action queried");
                    false
                }
            }
        } else {
            tracing::warn!(role, "Unknown role — access denied");
            false
        }
    }

    /// Get all available roles.
    pub fn list_roles(&self) -> Vec<&str> {
        self.roles.keys().map(|s| s.as_str()).collect()
    }

    /// Get permissions for a specific role.
    pub fn get_role_permissions(&self, role: &str) -> Option<&RolePermissions> {
        self.roles.get(role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::config::RolePermissions;

    fn test_roles() -> HashMap<String, RolePermissions> {
        let mut roles = HashMap::new();
        roles.insert(
            "admin".to_string(),
            RolePermissions {
                can_authorize: true,
                can_block: true,
                can_view_logs: true,
                can_configure: true,
                can_eject: true,
            },
        );
        roles.insert(
            "user".to_string(),
            RolePermissions {
                can_authorize: false,
                can_block: false,
                can_view_logs: true,
                can_configure: false,
                can_eject: true,
            },
        );
        roles.insert(
            "kiosk".to_string(),
            RolePermissions {
                can_authorize: false,
                can_block: false,
                can_view_logs: false,
                can_configure: false,
                can_eject: false,
            },
        );
        roles
    }

    #[test]
    fn test_admin_full_access() {
        let engine = RbacEngine::new(test_roles());
        assert!(engine.check_permission("admin", "authorize"));
        assert!(engine.check_permission("admin", "block"));
        assert!(engine.check_permission("admin", "configure"));
        assert!(engine.check_permission("admin", "view_logs"));
        assert!(engine.check_permission("admin", "eject"));
    }

    #[test]
    fn test_user_limited_access() {
        let engine = RbacEngine::new(test_roles());
        assert!(!engine.check_permission("user", "authorize"));
        assert!(!engine.check_permission("user", "block"));
        assert!(!engine.check_permission("user", "configure"));
        assert!(engine.check_permission("user", "view_logs"));
        assert!(engine.check_permission("user", "eject"));
    }

    #[test]
    fn test_kiosk_no_access() {
        let engine = RbacEngine::new(test_roles());
        assert!(!engine.check_permission("kiosk", "authorize"));
        assert!(!engine.check_permission("kiosk", "eject"));
        assert!(!engine.check_permission("kiosk", "view_logs"));
    }

    #[test]
    fn test_unknown_role_denied() {
        let engine = RbacEngine::new(test_roles());
        assert!(!engine.check_permission("hacker", "authorize"));
    }
}
