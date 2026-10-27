use crate::db::{self, FileRow, FolderRow};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub enum Identity {
    /// App-level (tenant admin): verified X-App-Key + HMAC signature.
    App(i64),
    /// User-level: verified user-context JWT.
    User { app_id: i64, user_id: String },
    /// Capability token (download path).
    Token(String),
    /// Internal admin (localhost).
    Admin,
}

impl Identity {
    pub fn app_id(&self) -> Option<i64> {
        match self {
            Identity::App(id) => Some(*id),
            Identity::User { app_id, .. } => Some(*app_id),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Delete,
    List,
    Export,
    ManageAcl,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Acl {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub delete: Vec<String>,
    #[serde(default)]
    pub list: Vec<String>,
    #[serde(default)]
    pub export: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub public_read: bool,
}

impl Acl {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_default()
    }

    fn action_list(&self, action: Action) -> &[String] {
        match action {
            Action::Read => &self.read,
            Action::Write => &self.write,
            Action::Delete => &self.delete,
            Action::List => &self.list,
            Action::Export => &self.export,
            Action::ManageAcl => &[],
        }
    }
}

fn match_subject(list: &[String], subject: &str) -> bool {
    list.iter().any(|s| s == subject || s == "*")
}

/// Evaluate an ACL for one subject (user_id) and action.
/// deny wins; owner allowed by default; otherwise allow-list / public read.
pub fn evaluate_acl(acl: &Acl, subject: &str, action: Action) -> bool {
    if match_subject(&acl.deny, subject) {
        return false;
    }
    if !acl.owner.is_empty() && acl.owner == subject {
        return true;
    }
    if action == Action::ManageAcl {
        return false;
    }
    if match_subject(acl.action_list(action), subject) {
        return true;
    }
    if action == Action::Read && acl.public_read {
        return true;
    }
    false
}

/// Effective ACL for a file: allow rules come from the file's own explicit
/// rules when present, otherwise from the nearest ancestor folder with rules.
/// `deny` is collected across the WHOLE folder chain and always wins — even
/// when the file has explicit allow rules (API spec: "deny is evaluated across
/// the whole chain first; a file-level allow cannot override an inherited
/// deny"); the file's owner keeps default access unless denied.
pub fn effective_acl(conn: &Connection, file: &FileRow) -> rusqlite::Result<Acl> {
    let own = Acl::from_json(&file.acl);
    let file_explicit = !is_empty_allow(&own) || !own.deny.is_empty();

    let mut allow_base = Acl {
        owner: own.owner.clone(),
        ..Default::default()
    };
    if file_explicit {
        // File rules override inherited allows (but never an inherited deny).
        allow_base.read = own.read;
        allow_base.write = own.write;
        allow_base.delete = own.delete;
        allow_base.list = own.list;
        allow_base.export = own.export;
        allow_base.public_read = own.public_read;
    } else {
        // Inherit from the nearest folder that has allow rules.
        let mut folder_id = file.folder_id;
        let mut guard = 0;
        while let Some(fid) = folder_id {
            guard += 1;
            if guard > 100 {
                break;
            }
            let folder: FolderRow = match db::folder_by_id(conn, fid)? {
                Some(f) => f,
                None => break,
            };
            let fa = Acl::from_json(&folder.acl);
            if is_empty_allow(&allow_base) && !is_empty_allow(&fa) {
                allow_base.read = fa.read;
                allow_base.write = fa.write;
                allow_base.delete = fa.delete;
                allow_base.list = fa.list;
                allow_base.export = fa.export;
                allow_base.public_read = fa.public_read;
            }
            folder_id = folder.parent_id;
        }
    }

    // Deny collection is independent of whether the file has explicit rules:
    // walk the whole ancestor chain and merge every deny, so an inherited
    // deny can never be overridden by a file-level allow.
    let mut denies = own.deny.clone();
    let mut folder_id = file.folder_id;
    let mut guard = 0;
    while let Some(fid) = folder_id {
        guard += 1;
        if guard > 100 {
            break;
        }
        let folder: FolderRow = match db::folder_by_id(conn, fid)? {
            Some(f) => f,
            None => break,
        };
        for d in &Acl::from_json(&folder.acl).deny {
            if !denies.contains(d) {
                denies.push(d.clone());
            }
        }
        folder_id = folder.parent_id;
    }
    allow_base.deny = denies;
    Ok(allow_base)
}

fn is_empty_allow(a: &Acl) -> bool {
    a.read.is_empty()
        && a.write.is_empty()
        && a.delete.is_empty()
        && a.list.is_empty()
        && a.export.is_empty()
        && !a.public_read
}

/// Authorize a user subject against a file for a given action (deny-by-default).
pub fn can_user_access_file(conn: &Connection, file: &FileRow, user: &str, action: Action) -> bool {
    match effective_acl(conn, file) {
        Ok(acl) => evaluate_acl(&acl, user, action),
        Err(_) => false, // fail-closed
    }
}

/// App-level identity acts as tenant admin: it may manage/export any file in its
/// own tenant. Reads through the app are allowed for tenant-scoped operations.
pub fn can_app_access_file(file: &FileRow, app_id: i64, action: Action) -> bool {
    if file.app_id != app_id {
        return false;
    }
    matches!(action, Action::Export | Action::ManageAcl | Action::List | Action::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(read: &[&str], deny: &[&str]) -> Acl {
        Acl {
            owner: "u_owner".into(),
            read: read.iter().map(|s| s.to_string()).collect(),
            write: vec![],
            delete: vec![],
            list: vec![],
            export: vec![],
            deny: deny.iter().map(|s| s.to_string()).collect(),
            public_read: false,
        }
    }

    #[test]
    fn deny_wins_over_allow_and_owner() {
        let a = acl(&["u_a", "u_b"], &["u_a", "u_owner"]);
        assert!(!evaluate_acl(&a, "u_a", Action::Read)); // deny beats allow
        assert!(!evaluate_acl(&a, "u_owner", Action::Read)); // deny beats owner default
        assert!(evaluate_acl(&a, "u_b", Action::Read)); // allow list works
    }

    #[test]
    fn owner_default_allowed() {
        let a = acl(&[], &[]);
        assert!(evaluate_acl(&a, "u_owner", Action::Read));
        assert!(!evaluate_acl(&a, "u_stranger", Action::Read));
    }

    #[test]
    fn wildcard_and_public_read() {
        let mut a = acl(&["*"], &[]);
        assert!(evaluate_acl(&a, "u_anyone", Action::Read));
        a.read = vec![];
        a.public_read = true;
        assert!(evaluate_acl(&a, "u_anyone", Action::Read));
        assert!(!evaluate_acl(&a, "u_anyone", Action::Write));
    }

    #[test]
    fn per_action_permissions() {
        let a = Acl {
            owner: "u_owner".into(),
            read: vec!["u_reader".into()],
            write: vec!["u_writer".into()],
            delete: vec![],
            list: vec![],
            export: vec![],
            deny: vec![],
            public_read: false,
        };
        assert!(evaluate_acl(&a, "u_reader", Action::Read));
        assert!(!evaluate_acl(&a, "u_reader", Action::Write));
        assert!(evaluate_acl(&a, "u_writer", Action::Write));
        assert!(!evaluate_acl(&a, "u_writer", Action::Delete));
    }
}
