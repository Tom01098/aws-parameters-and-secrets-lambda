use std::fmt::Debug;
use std::{env, sync::Arc};

use anyhow::{anyhow, Context, Result};
use sealed::sealed;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use static_assertions::assert_impl_all;

const PORT_NAME: &str = "PARAMETERS_SECRETS_EXTENSION_HTTP_PORT";
const SESSION_TOKEN_NAME: &str = "AWS_SESSION_TOKEN";
const TOKEN_HEADER_NAME: &str = "X-AWS-Parameters-Secrets-Token";

assert_impl_all!(Manager: Send, Sync, Debug, Clone);
assert_impl_all!(Secret: Send, Sync, Debug, Clone);
assert_impl_all!(VersionIdQuery: Send, Sync, Debug, Clone);
assert_impl_all!(VersionStageQuery: Send, Sync, Debug, Clone);

#[derive(Debug, Clone)]
pub struct Manager {
    connection: Arc<Connection>,
}

impl Manager {
    pub fn new() -> Result<Self> {
        let port = match env::var(PORT_NAME) {
            Ok(port) => port
                .parse()
                .context(format!("'{port}' is not a valid port"))?,
            Err(_) => 2773,
        };
        let token = env::var(SESSION_TOKEN_NAME).context(format!(
            "'{SESSION_TOKEN_NAME}' not set (are you not running in AWS Lambda?)",
        ))?;
        Ok(Self {
            connection: Arc::new(Connection {
                client: reqwest::blocking::Client::new(),
                port,
                token,
            }),
        })
    }

    pub fn get_secret(&self, query: impl Query) -> Secret {
        Secret {
            query: query.get_query_string(),
            connection: self.connection.clone(),
        }
    }
}

#[derive(Debug)]
struct Connection {
    client: reqwest::blocking::Client,
    port: u16,
    token: String,
}

impl Connection {
    fn get_secret(&self, query: &str) -> Result<String> {
        Ok(self.client
            .get(format!("http://localhost:{port}/secretsmanager/get?{query}", port = self.port))
            .header(TOKEN_HEADER_NAME, &self.token)
            .send()
            .context(
                "could not communicate with the Secrets Manager extension (are you not running in AWS Lambda with the 'AWS-Parameters-and-Secrets-Lambda-Extension' version 2 layer?)"
            )?
            .error_for_status()
            .context("received an error response from the Secrets Manager extension")?
            .json::<ExtensionResponse>()
            .context("invalid JSON received from Secrets Manager extension")?
            .secret_string)
    }
}

#[derive(Debug, Clone)]
pub struct Secret {
    query: String,
    connection: Arc<Connection>,
}

impl Secret {
    pub fn get_raw(&self) -> Result<String> {
        self.connection.get_secret(&self.query)
    }

    pub fn get_single(&self, name: impl AsRef<str>) -> Result<String> {
        let raw = &self.get_raw()?;
        let name = name.as_ref();
        let parsed: Value = serde_json::from_str(raw)
            .context("could not parse raw response from extension into json")?;
        let secret_value = parsed.get(name).ok_or_else(||
            anyhow!("'{name}' was not returned by the extension (are you querying for the right secret?)")
        )?;
        let secret = secret_value.as_str().ok_or_else(|| {
            anyhow!("'{name}' was in the response from the extension, but it was not a string")
        })?;
        Ok(String::from(secret))
    }

    pub fn get_typed<T: DeserializeOwned>(&self) -> Result<T> {
        let raw = self.get_raw()?;
        Ok(serde_json::from_str(&raw)?)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query
    }
}

impl Eq for Secret {}

#[derive(Deserialize)]
struct ExtensionResponse {
    #[serde(rename = "SecretString")]
    secret_string: String,
}

#[sealed]
pub trait Query {
    fn get_query_string(&self) -> String;
}

pub struct QueryBuilder<'a> {
    secret_id: &'a str,
}

impl<'a> QueryBuilder<'a> {
    pub fn new(secret_id: &'a str) -> Self {
        Self { secret_id }
    }

    pub fn with_version_id(self, version_id: &'a str) -> VersionIdQuery<'a> {
        VersionIdQuery {
            secret_id: self.secret_id,
            version_id,
        }
    }

    pub fn with_version_stage(self, version_stage: &'a str) -> VersionStageQuery<'a> {
        VersionStageQuery {
            secret_id: self.secret_id,
            version_stage,
        }
    }
}

#[sealed]
impl<T: AsRef<str>> Query for T {
    fn get_query_string(&self) -> String {
        format!("secretId={}", self.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct VersionIdQuery<'a> {
    secret_id: &'a str,
    version_id: &'a str,
}

#[sealed]
impl Query for VersionIdQuery<'_> {
    fn get_query_string(&self) -> String {
        format!("secretId={}&versionId={}", self.secret_id, self.version_id)
    }
}

#[derive(Debug, Clone)]
pub struct VersionStageQuery<'a> {
    secret_id: &'a str,
    version_stage: &'a str,
}

#[sealed]
impl Query for VersionStageQuery<'_> {
    fn get_query_string(&self) -> String {
        format!(
            "secretId={}&versionStage={}",
            self.secret_id, self.version_stage
        )
    }
}

#[cfg(test)]
mod tests {
    use std::env::VarError;

    use httpmock::MockServer;

    use super::*;

    #[test]
    fn test_manager_get_raw_secret() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200).body("{\"SecretString\": \"xyz\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let secret_value = manager.get_secret("some-secret").get_raw().unwrap();

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_raw_secret_from_version_id() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret")
                .query_param("versionId", "some-version");
            then.status(200).body("{\"SecretString\": \"xyz\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let secret_value = manager
                    .get_secret(QueryBuilder::new("some-secret").with_version_id("some-version"))
                    .get_raw()
                    .unwrap();

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_raw_secret_from_version_stage() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret")
                .query_param("versionStage", "some-stage");
            then.status(200).body("{\"SecretString\": \"xyz\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let secret_value = manager
                    .get_secret(QueryBuilder::new("some-secret").with_version_stage("some-stage"))
                    .get_raw()
                    .unwrap();

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_single_secret() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200)
                .body("{\"SecretString\": \"{\\\"name\\\": \\\"value\\\"}\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let secret_value = manager
                    .get_secret("some-secret")
                    .get_single("name")
                    .unwrap();

                assert_eq!(String::from("value"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_typed_secret() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct SecretType {
            name: String
        }

        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200)
                .body("{\"SecretString\": \"{\\\"name\\\": \\\"value\\\"}\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let secret_value = manager
                    .get_secret("some-secret")
                    .get_typed()
                    .unwrap();

                assert_eq!(SecretType { name: String::from("value") }, secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_no_session_token() {
        temp_env::with_var(SESSION_TOKEN_NAME, None::<String>, || {
            let err = Manager::new().unwrap_err();
            let source = err.source().unwrap().downcast_ref().unwrap();
            assert_eq!(VarError::NotPresent, *source);
        })
    }

    #[test]
    fn test_manager_invalid_json() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200).body("{");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let err = manager.get_secret("some-secret").get_raw().unwrap_err();

                assert_eq!(
                    "invalid JSON received from Secrets Manager extension",
                    err.to_string()
                );
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_no_extension() {
        temp_env::with_var(SESSION_TOKEN_NAME, Some("TOKEN"), || {
            let manager = Manager::new().unwrap();

            let err = manager.get_secret("some-secret").get_raw().unwrap_err();

            assert_eq!(
                "could not communicate with the Secrets Manager extension (are you not running in AWS Lambda with the 'AWS-Parameters-and-Secrets-Lambda-Extension' version 2 layer?)",
                err.to_string()
            );
        });
    }

    #[test]
    fn test_manager_server_returns_non_200_status_code() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(500);
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let err = manager
                    .get_secret(String::from("some-secret"))
                    .get_raw()
                    .unwrap_err();

                assert_eq!(
                    "received an error response from the Secrets Manager extension",
                    err.to_string()
                )
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_fails_when_port_is_not_an_integer() {
        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some("xyz")),
            ],
            || {
                let err = Manager::new().unwrap_err();
                assert_eq!("'xyz' is not a valid port", err.to_string())
            },
        )
    }

    #[test]
    fn test_manager_fails_when_port_is_not_a_u16() {
        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some("70000")),
            ],
            || {
                let err = Manager::new().unwrap_err();
                assert_eq!("'70000' is not a valid port", err.to_string())
            },
        )
    }

    #[test]
    fn test_manager_default_port_is_2773() {
        temp_env::with_var(SESSION_TOKEN_NAME, Some("TOKEN"), || {
            let manager = Manager::new().unwrap();
            assert_eq!(2773, manager.connection.port);
        })
    }

    #[test]
    fn test_manager_get_single_secret_not_found() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200).body("{\"SecretString\": \"{}\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let err = manager
                    .get_secret("some-secret")
                    .get_single("name")
                    .unwrap_err();

                assert_eq!("'name' was not returned by the extension (are you querying for the right secret?)", err.to_string());
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_single_secret_incorrect_type() {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method("GET")
                .path("/secretsmanager/get")
                .query_param("secretId", "some-secret");
            then.status(200)
                .body("{\"SecretString\": \"{\\\"name\\\": 1}\"}");
        });

        temp_env::with_vars(
            vec![
                (SESSION_TOKEN_NAME, Some("TOKEN")),
                (PORT_NAME, Some(server.port().to_string().as_ref())),
            ],
            || {
                let manager = Manager::new().unwrap();

                let err = manager
                    .get_secret("some-secret")
                    .get_single("name")
                    .unwrap_err();

                assert_eq!(
                    "'name' was in the response from the extension, but it was not a string",
                    err.to_string()
                );
            },
        );

        mock.assert();
    }
}
