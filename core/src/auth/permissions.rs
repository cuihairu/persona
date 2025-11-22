use serde::{Deserialize, Serialize};

/// Permission levels for identity operations
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    /// Read-only access to identities
    Read,

    /// Ability to create new identities
    Create,

    /// Ability to modify existing identities
    Update,

    /// Ability to delete identities
    Delete,

    /// Administrative access (all permissions)
    Admin,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Create => write!(f, "create"),
            Permission::Update => write!(f, "update"),
            Permission::Delete => write!(f, "delete"),
            Permission::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for Permission {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" => Ok(Permission::Read),
            "create" => Ok(Permission::Create),
            "update" => Ok(Permission::Update),
            "delete" => Ok(Permission::Delete),
            "admin" => Ok(Permission::Admin),
            _ => Err(format!("Invalid permission: {}", s)),
        }
    }
}

/// Permission checker for operations
pub struct PermissionChecker {
    permissions: Vec<Permission>,
}

impl PermissionChecker {
    /// Create a new permission checker
    pub fn new(permissions: Vec<Permission>) -> Self {
        Self { permissions }
    }

    /// Check if a specific permission is granted
    pub fn has_permission(&self, required: &Permission) -> bool {
        // Admin permission grants all access
        if self.permissions.contains(&Permission::Admin) {
            return true;
        }

        self.permissions.contains(required)
    }

    /// Check if any of the specified permissions are granted
    pub fn has_any_permission(&self, required: &[Permission]) -> bool {
        if self.permissions.contains(&Permission::Admin) {
            return true;
        }

        required.iter().any(|p| self.permissions.contains(p))
    }

    /// Check if all specified permissions are granted
    pub fn has_all_permissions(&self, required: &[Permission]) -> bool {
        if self.permissions.contains(&Permission::Admin) {
            return true;
        }

        required.iter().all(|p| self.permissions.contains(p))
    }

    /// Get all granted permissions
    pub fn get_permissions(&self) -> &[Permission] {
        &self.permissions
    }
}

/// Default permissions for different user roles
impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new(vec![
            Permission::Read,
            Permission::Create,
            Permission::Update,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_display() {
        assert_eq!(Permission::Read.to_string(), "read");
        assert_eq!(Permission::Admin.to_string(), "admin");
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!("read".parse::<Permission>().unwrap(), Permission::Read);
        assert_eq!("ADMIN".parse::<Permission>().unwrap(), Permission::Admin);
        assert!("invalid".parse::<Permission>().is_err());
    }

    #[test]
    fn test_permission_checker() {
        let checker = PermissionChecker::new(vec![Permission::Read, Permission::Create]);

        assert!(checker.has_permission(&Permission::Read));
        assert!(checker.has_permission(&Permission::Create));
        assert!(!checker.has_permission(&Permission::Delete));

        let admin_checker = PermissionChecker::new(vec![Permission::Admin]);
        assert!(admin_checker.has_permission(&Permission::Delete));
    }
}
