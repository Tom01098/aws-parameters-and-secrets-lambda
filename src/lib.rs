use std::fmt::Debug;
use std::{env, sync::Arc};

use anyhow::{Context, Result};
use serde::Deserialize;

const PORT_NAME: &str = "PARAMETERS_SECRETS_EXTENSION_HTTP_PORT";
const SESSION_TOKEN_NAME: &str = "AWS_SESSION_TOKEN";
const TOKEN_HEADER_NAME: &str = "X-AWS-Parameters-Secrets-Token";

#[derive(Debug)]
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

    pub fn get_secret(&self, name: String) -> Result<Secret> {
        Ok(Secret {
            name,
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
    fn get_secret(&self, name: &str) -> Result<String> {
        Ok(self.client
            .get(format!(
                "http://localhost:{}/secretsmanager/get?secretId={}",
                self.port, name
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

#[derive(Debug)]
pub struct Secret {
    name: String,
    connection: Arc<Connection>,
}

impl Secret {
    pub fn get_raw(&self) -> Result<String> {
        self.connection.get_secret(&self.name)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Secret {}

#[derive(Deserialize)]
pub struct ExtensionResponse {
    #[serde(rename = "SecretString")]
    secret_string: String,
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
                    .get_secret(String::from("some-secret"))
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
                    .get_secret(String::from("some-secret"))
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
                .get_secret(String::from("some-secret"))
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
