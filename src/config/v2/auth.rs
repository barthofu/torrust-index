use std::fmt;

use serde::{Deserialize, Serialize};

/// Authentication options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Auth {
    /// The secret key used to sign JWT tokens.
    #[serde(default = "Auth::default_user_claim_token_pepper")]
    pub user_claim_token_pepper: ClaimTokenPepper,

    /// The password constraints
    #[serde(default = "Auth::default_password_constraints")]
    pub password_constraints: PasswordConstraints,

    /// Optional OpenID Connect configuration
    #[serde(default = "Auth::default_oidc")]
    pub oidc: Option<Oidc>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            password_constraints: Self::default_password_constraints(),
            user_claim_token_pepper: Self::default_user_claim_token_pepper(),
            oidc: Self::default_oidc(),
        }
    }
}

impl Auth {
    pub fn override_user_claim_token_pepper(&mut self, user_claim_token_pepper: &str) {
        self.user_claim_token_pepper = ClaimTokenPepper::new(user_claim_token_pepper);
    }

    fn default_user_claim_token_pepper() -> ClaimTokenPepper {
        ClaimTokenPepper::new("MaxVerstappenWC2021")
    }

    fn default_password_constraints() -> PasswordConstraints {
        PasswordConstraints::default()
    }

    fn default_oidc() -> Option<Oidc> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimTokenPepper(String);

impl ClaimTokenPepper {
    /// # Panics
    ///
    /// Will panic if the key if empty.
    #[must_use]
    pub fn new(key: &str) -> Self {
        assert!(!key.is_empty(), "secret key cannot be empty");

        Self(key.to_owned())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for ClaimTokenPepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Oidc {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub issuer_url: String,

    #[serde(default)]
    pub client_id: String,

    #[serde(default)]
    pub client_secret: String,

    /// Callback path on this API (joined to base URL)
    #[serde(default = "Oidc::default_redirect_path")]
    pub redirect_path: String,

    /// Requested scopes
    #[serde(default = "Oidc::default_scopes")]
    pub scopes: Vec<String>,

    /// Claim name to use for local username if present
    #[serde(default = "Oidc::default_username_claim")]
    pub username_claim: String,

    /// Claim name to use for email
    #[serde(default = "Oidc::default_email_claim")]
    pub email_claim: String,

    /// Optional URL in the GUI to redirect to after login, e.g. "http://localhost:3000/oidc-callback"
    #[serde(default)]
    pub post_login_redirect_url: Option<String>,

    /// Claim name to read group memberships from (ID token or userinfo)
    #[serde(default = "Oidc::default_groups_claim")]
    pub groups_claim: String,

    /// Name of the group whose membership grants admin rights
    #[serde(default)]
    pub admin_group: Option<String>,
}

impl Oidc {
    fn default_redirect_path() -> String {
        "/v1/user/oidc/callback".to_string()
    }

    fn default_scopes() -> Vec<String> {
        vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
    }

    fn default_username_claim() -> String {
        "preferred_username".to_string()
    }

    fn default_email_claim() -> String {
        "email".to_string()
    }

    fn default_groups_claim() -> String {
        "groups".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordConstraints {
    /// The maximum password length.
    #[serde(default = "PasswordConstraints::default_max_password_length")]
    pub max_password_length: usize,
    /// The minimum password length.
    #[serde(default = "PasswordConstraints::default_min_password_length")]
    pub min_password_length: usize,
}

impl Default for PasswordConstraints {
    fn default() -> Self {
        Self {
            max_password_length: Self::default_max_password_length(),
            min_password_length: Self::default_min_password_length(),
        }
    }
}

impl PasswordConstraints {
    fn default_min_password_length() -> usize {
        6
    }

    fn default_max_password_length() -> usize {
        64
    }
}
