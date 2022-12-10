use std::env;

use anyhow::{Context, Result};
use serde::Deserialize;

const PORT_NAME: &str = "PARAMETERS_SECRETS_EXTENSION_HTTP_PORT";
const SESSION_TOKEN_NAME: &str = "AWS_SESSION_TOKEN";
const TOKEN_HEADER_NAME: &str = "X-AWS-Parameters-Secrets-Token";

pub struct Manager {
    client: reqwest::blocking::Client,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn get_secret(&self, name: String) -> Result<Secret> {
        let token = env::var(SESSION_TOKEN_NAME).context(format!(
            "'{}' not set (are you not running in AWS Lambda?)",
            SESSION_TOKEN_NAME
        ))?;

        let port = env::var(PORT_NAME).unwrap_or_else(|_| String::from("2773"));

        self.client
            .get(format!(
                "http://localhost:{}/secretsmanager/get?secretId={}",
                port, name
            ))
            .header(TOKEN_HEADER_NAME, token)
            .send()
            .unwrap()
            .json()
            .context("invalid JSON received from Secrets Manager extension")
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Secret {
    #[serde(rename = "SecretString")]
    pub string: String,
}

#[cfg(test)]
mod tests {
    use std::env::VarError;

    use httpmock::MockServer;

    use super::*;

    #[test]
    fn test_default_manager_get_single_secret() {
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
                let manager = Manager::default();

                let secret_value = manager
                    .get_secret(String::from("some-secret"))
                    .unwrap()
                    .string;

                assert_eq!(String::from("xyz"), secret_value);
            },
        );

        mock.assert();
    }

    #[test]
    fn test_default_manager_no_session_token() {
        temp_env::with_var(SESSION_TOKEN_NAME, None::<String>, || {
            let err = Manager::default().get_secret(String::from("")).unwrap_err();
            let source = err.source().unwrap().downcast_ref().unwrap();
            assert_eq!(VarError::NotPresent, *source);
        })
    }

    #[test]
    fn test_default_manager_invalid_json() {
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
                let manager = Manager::default();

                let err = manager.get_secret(String::from("some-secret")).unwrap_err();

                assert_eq!(
                    "invalid JSON received from Secrets Manager extension",
                    err.to_string()
                );
            },
        );

        mock.assert();
    }
}
