//! Cache AWS Secrets Manager secrets in your AWS Lambda function, reducing latency (we don't need to query another service) and cost ([Secrets Manager charges based on queries]).
//! 
//! # Quickstart
//! Add the [AWS Parameters and Secrets Lambda Extension] [layer to your Lambda function]. Only version 2 of this layer is currently supported.
//! 
//! Assuming a secret exists with the name "backend-server" containing a key/value pair with a key of "api_key" and a value of 
//! "dd96eeda-16d3-4c86-975f-4986e603ec8c" (our super secret API key to our backend), this code will get the secret from the cache, querying
//! Secrets Manager if it is not in the cache, and present it in a strongly-typed `BackendServer` object. 
//! 
//! ```rust
//! use aws_parameters_and_secrets_lambda::Manager;
//! use serde::Deserialize;
//! 
//! #[derive(Deserialize)]
//! struct BackendServer {
//!     api_key: String
//! }
//! 
//! # let server = httpmock::MockServer::start();
//! # let mock = server.mock(|when, then| {
//! #     when.method("GET").path("/secretsmanager/get");
//! #     then.status(200).body("{\"SecretString\": \"{\\\"api_key\\\": \\\"dd96eeda-16d3-4c86-975f-4986e603ec8c\\\"}\"}");
//! # });
//! # 
//! # temp_env::with_vars(
//! #     vec![
//! #         ("AWS_SESSION_TOKEN", Some("xyz")),
//! #         ("PARAMETERS_SECRETS_EXTENSION_HTTP_PORT", Some(&server.port().to_string()))
//! #     ],
//! #     || {
//! #         tokio_test::block_on(
//! #             std::panic::AssertUnwindSafe(
//! #                 async {
//! let manager = Manager::default();
//! let secret = manager.get_secret("backend-server");
//! let secret_value: BackendServer = secret.get_typed().await?;
//! assert_eq!("dd96eeda-16d3-4c86-975f-4986e603ec8c", secret_value.api_key);
//! #                     Ok::<_, anyhow::Error>(())
//! #                 }
//! #             )
//! #         );
//! #     }
//! # );
//! #
//! # mock.assert();
//! ```
//! 
//! [Secrets Manager charges based on queries]: https://aws.amazon.com/secrets-manager/pricing/
//! [AWS Parameters and Secrets Lambda Extension]: https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html
//! [layer to your Lambda function]: https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html

use std::fmt::Debug;
use std::{env, sync::Arc};

use anyhow::{anyhow, Context, Result};
use sealed::sealed;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use static_assertions::assert_impl_all;

const PORT_NAME: &str = "PARAMETERS_SECRETS_EXTENSION_HTTP_PORT";
const SESSION_TOKEN_NAME: &str = "AWS_SESSION_TOKEN";
const TOKEN_HEADER_NAME: &str = "X-AWS-Parameters-Secrets-Token";

assert_impl_all!(Manager: Send, Sync, Debug, Clone);
assert_impl_all!(Secret: Send, Sync, Debug, Clone);
assert_impl_all!(VersionIdQuery: Send, Sync, Debug, Clone);
assert_impl_all!(VersionStageQuery: Send, Sync, Debug, Clone);

#[derive(Debug)]
#[must_use = "construct a `Manager` with the `build` method"]
pub struct ManagerBuilder {
    port: Option<u16>,
    token: Option<String>,
}

impl ManagerBuilder {
    pub fn new() -> Self {
        Self {
            port: None,
            token: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub fn build(self) -> Result<Manager> {
        let port = match self.port {
            Some(port) => port,
            None => match env::var(PORT_NAME) {
                Ok(port) => port
                    .parse()
                    .context(format!("'{port}' is not a valid port"))?,
                Err(_) => 2773,
            },
        };

        let token = match self.token {
            Some(token) => token,
            None => env::var(SESSION_TOKEN_NAME).context(format!(
                "'{SESSION_TOKEN_NAME}' not set (are you not running in AWS Lambda?)",
            ))?,
        };

        Ok(Manager {
            connection: Arc::new(Connection {
                client: reqwest::Client::new(),
                port,
                token,
            }),
        })
    }
}

impl Default for ManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Manager {
    connection: Arc<Connection>,
}

impl Manager {
    pub fn get_secret(&self, query: impl Query) -> Secret {
        Secret {
            query: query.get_query_string(),
            connection: self.connection.clone(),
        }
    }
}

impl Default for Manager {
    fn default() -> Self {
        ManagerBuilder::new().build().unwrap()
    }
}

#[derive(Debug)]
struct Connection {
    client: reqwest::Client,
    port: u16,
    token: String,
}

impl Connection {
    async fn get_secret(&self, query: &str) -> Result<String> {
        Ok(self.client
            .get(format!("http://localhost:{port}/secretsmanager/get?{query}", port = self.port))
            .header(TOKEN_HEADER_NAME, &self.token)
            .send()
            .await
            .context(
                "could not communicate with the Secrets Manager extension (are you not running in AWS Lambda with the 'AWS-Parameters-and-Secrets-Lambda-Extension' version 2 layer?)"
            )?
            .error_for_status()
            .context("received an error response from the Secrets Manager extension")?
            .json::<ExtensionResponse>()
            .await
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
    pub async fn get_raw(&self) -> Result<String> {
        self.connection.get_secret(&self.query).await
    }

    pub async fn get_single(&self, name: impl AsRef<str>) -> Result<String> {
        let raw = &self.get_raw().await?;
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

    pub async fn get_typed<T: DeserializeOwned>(&self) -> Result<T> {
        let raw = self.get_raw().await?;
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

#[must_use = "continue building a query with the `with_version_id` or `with_version_stage` method"]
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
    use std::{collections::HashMap, env::VarError, future::Future};

    use httpmock::MockServer;

    use maplit::hashmap;

    use super::*;

    struct MockServerConfig<'a> {
        query: HashMap<&'a str, &'a str>,
        status: u16,
        response: &'a str,
    }

    async fn with_mock_server<T: Future>(config: MockServerConfig<'_>, f: impl FnOnce(u16) -> T) {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            let mut when = when.method("GET").path("/secretsmanager/get");

            for (name, value) in config.query {
                when = when.query_param(name, value);
            }
            then.status(config.status).body(config.response);
        });

        f(server.port()).await;

        mock.assert();
    }

    #[tokio::test]
    async fn test_manager_get_raw_secret() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{\"SecretString\": \"xyz\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let secret_value = manager.get_secret("some-secret").get_raw().await.unwrap();

            assert_eq!(String::from("xyz"), secret_value);
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_raw_secret_from_version_id() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret", "versionId" => "some-version"},
            status: 200,
            response: "{\"SecretString\": \"xyz\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let secret_value = manager
                .get_secret(QueryBuilder::new("some-secret").with_version_id("some-version"))
                .get_raw()
                .await
                .unwrap();

            assert_eq!(String::from("xyz"), secret_value);
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_raw_secret_from_version_stage() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret", "versionStage" => "some-stage"},
            status: 200,
            response: "{\"SecretString\": \"xyz\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let secret_value = manager
                .get_secret(QueryBuilder::new("some-secret").with_version_stage("some-stage"))
                .get_raw()
                .await
                .unwrap();

            assert_eq!(String::from("xyz"), secret_value);
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_single_secret() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{\"SecretString\": \"{\\\"name\\\": \\\"value\\\"}\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let secret_value = manager
                .get_secret("some-secret")
                .get_single("name")
                .await
                .unwrap();

            assert_eq!(String::from("value"), secret_value);
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_typed_secret() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct SecretType {
            name: String,
        }

        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{\"SecretString\": \"{\\\"name\\\": \\\"value\\\"}\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let secret_value = manager.get_secret("some-secret").get_typed().await.unwrap();

            assert_eq!(
                SecretType {
                    name: String::from("value")
                },
                secret_value
            );
        })
        .await;
    }

    #[test]
    fn test_manager_builder_no_session_token() {
        temp_env::with_var(SESSION_TOKEN_NAME, None::<String>, || {
            let err = ManagerBuilder::new().build().unwrap_err();
            let source = err.source().unwrap().downcast_ref().unwrap();
            assert_eq!(VarError::NotPresent, *source);
        })
    }

    #[tokio::test]
    async fn test_manager_invalid_json() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let err = manager
                .get_secret("some-secret")
                .get_raw()
                .await
                .unwrap_err();

            assert_eq!(
                "invalid JSON received from Secrets Manager extension",
                err.to_string()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_no_extension() {
        let manager = ManagerBuilder::new()
            .with_token(String::from("TOKEN"))
            .with_port(65535)
            .build()
            .unwrap();

        let err = manager
            .get_secret("some-secret")
            .get_raw()
            .await
            .unwrap_err();

        assert_eq!(
            "could not communicate with the Secrets Manager extension (are you not running in AWS Lambda with the 'AWS-Parameters-and-Secrets-Lambda-Extension' version 2 layer?)",
            err.to_string()
        );
    }

    #[tokio::test]
    async fn test_manager_server_returns_non_200_status_code() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 500,
            response: "",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let err = manager
                .get_secret(String::from("some-secret"))
                .get_raw()
                .await
                .unwrap_err();

            assert_eq!(
                "received an error response from the Secrets Manager extension",
                err.to_string()
            )
        })
        .await;
    }

    #[test]
    fn test_manager_builder_fails_when_port_is_not_an_integer() {
        temp_env::with_var(PORT_NAME, Some("xyz"), || {
            let err = ManagerBuilder::new()
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap_err();
            assert_eq!("'xyz' is not a valid port", err.to_string())
        })
    }

    #[test]
    fn test_manager_fails_when_port_is_not_a_u16() {
        temp_env::with_var(PORT_NAME, Some("70000"), || {
            let err = ManagerBuilder::new()
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap_err();
            assert_eq!("'70000' is not a valid port", err.to_string())
        })
    }

    #[test]
    fn test_manager_default_port_is_2773() {
        temp_env::with_var_unset(SESSION_TOKEN_NAME, || {
            let manager = ManagerBuilder::new()
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();
            assert_eq!(2773, manager.connection.port);
        });
    }

    #[tokio::test]
    async fn test_manager_get_single_secret_not_found() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{\"SecretString\": \"{}\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let err = manager
                .get_secret("some-secret")
                .get_single("name")
                .await
                .unwrap_err();

            assert_eq!(
                "'name' was not returned by the extension (are you querying for the right secret?)",
                err.to_string()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_single_secret_incorrect_type() {
        let config = MockServerConfig {
            query: hashmap! {"secretId" => "some-secret"},
            status: 200,
            response: "{\"SecretString\": \"{\\\"name\\\": 1}\"}",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let err = manager
                .get_secret("some-secret")
                .get_single("name")
                .await
                .unwrap_err();

            assert_eq!(
                "'name' was in the response from the extension, but it was not a string",
                err.to_string()
            );
        })
        .await;
    }
}
