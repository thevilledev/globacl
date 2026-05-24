#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPrincipal {
    pub identity: String,
    pub scopes: Vec<String>,
    pub authenticated: bool,
}

impl AuthPrincipal {
    pub fn anonymous() -> Self {
        Self {
            identity: "anonymous".to_owned(),
            scopes: Vec::new(),
            authenticated: false,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|candidate| candidate == "*" || candidate == scope)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    tokens: HashMap<String, AuthPrincipal>,
}

impl AuthConfig {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn from_spec(spec: &str) -> Result<Self> {
        let mut tokens = HashMap::new();
        for raw_entry in spec.split(';').map(str::trim).filter(|entry| !entry.is_empty()) {
            let (token, principal_spec) = raw_entry.split_once('=').ok_or_else(|| {
                GlobAclError::Parse(
                    "auth token entries must be token=identity:scope,scope".to_owned(),
                )
            })?;
            let token = token.trim();
            if token.is_empty() {
                return Err(GlobAclError::Parse("auth token cannot be empty".to_owned()));
            }
            let (identity, scopes_spec) = principal_spec
                .trim()
                .split_once(':')
                .unwrap_or((principal_spec.trim(), ""));
            let identity = sanitize_auth_identity(identity.trim())?;
            let scopes = scopes_spec
                .split(',')
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            tokens.insert(
                token.to_owned(),
                AuthPrincipal {
                    identity,
                    scopes,
                    authenticated: true,
                },
            );
        }
        Ok(Self { tokens })
    }

    pub fn is_enabled(&self) -> bool {
        !self.tokens.is_empty()
    }

    pub fn require_scope(
        &self,
        request: &HttpRequest,
        scope: &str,
    ) -> std::result::Result<AuthPrincipal, AuthFailure> {
        if !self.is_enabled() {
            return Ok(AuthPrincipal::anonymous());
        }
        let token = request.bearer_token().ok_or(AuthFailure::MissingBearer)?;
        let principal = self.tokens.get(token).ok_or(AuthFailure::InvalidBearer)?;
        if principal.has_scope(scope) {
            Ok(principal.clone())
        } else {
            Err(AuthFailure::InsufficientScope)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthFailure {
    MissingBearer,
    InvalidBearer,
    InsufficientScope,
}

impl AuthFailure {
    pub fn status_code(self) -> u16 {
        match self {
            Self::MissingBearer | Self::InvalidBearer => 401,
            Self::InsufficientScope => 403,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::MissingBearer => "missing_bearer_token",
            Self::InvalidBearer => "invalid_bearer_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }
}

pub fn auth_config_from_env_var(name: &str) -> Result<AuthConfig> {
    match std::env::var(name) {
        Ok(spec) if !spec.trim().is_empty() => AuthConfig::from_spec(&spec),
        _ => Ok(AuthConfig::disabled()),
    }
}

pub fn write_auth_failure_response(
    stream: &mut TcpStream,
    failure: AuthFailure,
    required_scope: &str,
) -> Result<()> {
    let body = format!(
        "status=rejected\nreason={}\nrequired_scope={required_scope}\n",
        failure.reason()
    );
    write_http_response(stream, failure.status_code(), "text/plain", body.as_bytes())
}

fn sanitize_auth_identity(identity: &str) -> Result<String> {
    if identity.is_empty() {
        return Err(GlobAclError::Parse(
            "auth identity cannot be empty".to_owned(),
        ));
    }
    if identity
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@' | ':'))
    {
        Ok(identity.to_owned())
    } else {
        Err(GlobAclError::Parse(format!(
            "auth identity {identity:?} contains unsupported characters"
        )))
    }
}

pub fn sanitize_audit_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@' | ':') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
