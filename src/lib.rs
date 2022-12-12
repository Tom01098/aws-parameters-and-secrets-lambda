use std::fmt::Debug;
use std::{env, sync::Arc};

use anyhow::{Context, Result};
use sealed::sealed;
use serde::Deserialize;
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
        let port = env::var(PORT_NAME).unwrap_or_else(|_| String::from("2773"));
        let token = env::var(SESSION_TOKEN_NAME).context(format!(
            "'{}' not set (are you not running in AWS Lambda?)",
            SESSION_TOKEN_NAME
        ))?;
        Ok(Self {
            connection: Arc::new(Connection {
                client: reqwest::blocking::Client::new(),
                port,
                token,
            }),
        })
    }

    pub fn get_secret(&self, query: impl Query) -> Result<Secret> {
        Ok(Secret {
            query: query.get_query_string(),
            connection: self.connection.clone(),
        })
    }
}

#[derive(Debug)]
struct Connection {
    client: reqwest::blocking::Client,
    port: String,
    token: String,
}

impl Connection {
    fn get_secret(&self, query: &str) -> Result<String> {
        Ok(self.client
            .get(format!(
                "http://localhost:{}/secretsmanager/get?{}",
                self.port, query
            ))
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
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query
    }
}

impl Eq for Secret {}

#[derive(Deserialize)]
pub struct ExtensionResponse {
    #[serde(rename = "SecretString")]
    secret_string: String,
}

#[sealed]
pub trait Query {
    fn get_query_string(&self) -> String;
}

#[sealed]
impl Query for &str {
    fn get_query_string(&self) -> String {
        format!("secretId={}", self)
    }
}

#[sealed]
impl Query for String {
    fn get_query_string(&self) -> String {
        format!("secretId={}", self)
    }
}

#[derive(Debug, Clone)]
pub struct VersionIdQuery {
    secret_id: String,
    version_id: String,
}

impl VersionIdQuery {
    pub fn new(secret_id: String, version_id: String) -> Self {
        Self {
            secret_id,
            version_id,
        }
    }
}

#[sealed]
impl Query for VersionIdQuery {
    fn get_query_string(&self) -> String {
        format!("secretId={}&versionId={}", self.secret_id, self.version_id)
    }
}

#[derive(Debug, Clone)]
pub struct VersionStageQuery {
    secret_id: String,
    version_stage: String,
}

impl VersionStageQuery {
    pub fn new(secret_id: String, version_stage: String) -> Self {
        Self {
            secret_id,
            version_stage,
        }
    }
}

#[sealed]
impl Query for VersionStageQuery {
    fn get_query_string(&self) -> String {
        format!("secretId={}&versionStage={}", self.secret_id, self.version_stage)
    }
}

#[cfg(test)]
mod tests {
    use std::env::VarError;

    use httpmock::MockServer;

    use super::*;

    #[test]
    fn test_manager_get_single_secret() {
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
                let manager = Manager::new();

                let secret_value = manager
                    .unwrap()
                    .get_secret("some-secret")
                    .unwrap()
                    .get_raw()
                    .unwrap();

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_single_secret_from_version_id() {
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
                let manager = Manager::new();

                let secret_value = manager
                    .unwrap()
                    .get_secret(VersionIdQuery::new(
                        String::from("some-secret"),
                        String::from("some-version"),
                    ))
                    .unwrap()
                    .get_raw()
                    .unwrap();

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_manager_get_single_secret_from_version_stage() {
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
                let manager = Manager::new();

                let secret_value = manager
                    .unwrap()
                    .get_secret(VersionStageQuery::new(
                        String::from("some-secret"),
                        String::from("some-stage"),
                    ))
                    .unwrap()
                    .get_raw()
                    .unwrap();

                assert_eq!(String::from("xyz"), secret_value);
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

                let err = manager
                    .get_secret("some-secret")
                    .unwrap()
                    .get_raw()
                    .unwrap_err();

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

            let err = manager
                .get_secret("some-secret")
                .unwrap()
                .get_raw()
                .unwrap_err();

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
                    .unwrap()
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
}
