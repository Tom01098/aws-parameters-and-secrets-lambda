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

#![deny(missing_docs)]

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

/// Flexible builder for a [`Manager`].
///
/// This sample should be all you ever need to use. It is identical to [`Manager::default`](struct.Manager.html#method.default) but does not panic on failure.
///
/// ```rust
/// # use aws_parameters_and_secrets_lambda::ManagerBuilder;
/// # temp_env::with_var("AWS_SESSION_TOKEN", Some("xyz"), || {
/// let manager = ManagerBuilder::new().build()?;
/// # Ok::<_, anyhow::Error>(())
/// # });
/// ```
#[derive(Debug)]
#[must_use = "construct a `Manager` with the `build` method"]
pub struct ManagerBuilder {
    port: Option<u16>,
    token: Option<String>,
}

impl ManagerBuilder {
    /// Create a new builder with the default values.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            port: None,
            token: None,
        }
    }

    /// Use the given port for the extension server instead of the default.
    ///
    /// If this is not called before [`build`](Self::build), then the "PARAMETERS_SECRETS_EXTENSION_HTTP_PORT"
    /// environment variable will be used, or 2773 if this is not set.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Use the given token to authenticate with the extension server instead of the default.
    ///
    /// If this is not called before [`build`](Self::build), then the "AWS_SESSION_TOKEN"
    /// environment variable will be used.
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    /// Create a [`Manager`] from the given values.
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

/// Manages connections to the cache. Create one via a [`ManagerBuilder`].
///
/// Ideally, only one of these should exist in a single executable (cloning is fine as it will reuse the connections).
#[derive(Debug, Clone)]
pub struct Manager {
    connection: Arc<Connection>,
}

impl Manager {
    /// Get a representation of a secret that matches a given query.
    ///
    /// Note that this does not return the value of the secret; see [`Secret`] for how to get it.
    pub fn get_secret(&self, query: impl Query) -> Secret {
        Secret {
            query: query.get_query_string(),
            connection: self.connection.clone(),
        }
    }
    /// Get a representation of a parameter that matches a given parameter name.
    ///
    /// For parameters of type `SecureString`, `with_decryption` must be set to `true.
    /// Additionally, the lambda role must have the `kms:Decrypt` permission.
    ///
    /// Note that this does not return the value of the parameter; see [`Parameter`] for how to get it.
    pub fn get_parameter(&self, param_name: &str, with_decryption: bool) -> Parameter {
        Parameter {
            query: format!(
                "name={}&withDecryption={}",
                param_name,
                with_decryption
            ),
            connection: self.connection.clone(),
        }
    }
}

impl Default for Manager {
    /// Initialise a default `Manager` from the environment.
    ///
    /// # Panics
    /// If the AWS Lambda environment is invalid, this will panic.
    /// It is strongly recommended to use a [`ManagerBuilder`] instead as it is more flexible and has proper error handling.
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
    async fn get_from_request(&self, url: &str) -> Result<reqwest::Response> {
        self.client
            .get(url)
            .header(TOKEN_HEADER_NAME, &self.token)
            .send()
            .await
            .context(
                "could not communicate with the Secrets Manager extension (are you not running in AWS Lambda with the 'AWS-Parameters-and-Secrets-Lambda-Extension' version 2 layer?)"
            )?
            .error_for_status()
            .context("received an error response from the Secrets Manager extension")
    }

    async fn get_secret(&self, query: &str) -> Result<String> {
        let url = format!("http://localhost:{port}/secretsmanager/get?{query}", port = self.port);
        Ok(self.get_from_request(&url).await?
            .json::<ExtensionResponseSecret>()
            .await
            .context("invalid JSON received from Secrets Manager extension")?
            .secret_string)
    }

    async fn get_parameter(&self, query: &str) -> Result<ExtensionResponseParam> {
        let url = format!("http://localhost:{port}/systemsmanager/parameters/get?{query}", port = self.port);
        self.get_from_request(&url).await?
            .json::<ExtensionResponseParam>()
            .await
            .context("invalid JSON received from Secrets Manager extension")
    }
}

/// A representation of a secret in Secrets Manager.
#[derive(Debug, Clone)]
pub struct Secret {
    query: String,
    connection: Arc<Connection>,
}

impl Secret {
    /// Get the plaintext value of this secret.
    /// 
    /// Usually, this is in json format, but it can be any data format that you provide to Secrets Manager.
    pub async fn get_raw(&self) -> Result<String> {
        self.connection.get_secret(&self.query).await
    }

    /// Get a value by name from within this secret.
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

    /// Get the value of this secret, represented as a strongly-typed T.
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
struct ExtensionResponseSecret {
    #[serde(rename = "SecretString")]
    secret_string: String,
}

/// A representation of a parameter in Parameter Store in SSM.
#[derive(Debug, Clone)]
pub struct Parameter {
    query: String,
    connection: Arc<Connection>,
}

impl Parameter {
    /// Get the plaintext value of this parameter.
    pub async fn get_raw(&self) -> Result<String> {
        Ok(self.get_as_full_extension_response().await?.parameter.value)
    }

    /// Get the value of this parameter, represented as a strongly-typed T.
    pub async fn get_typed<T: DeserializeOwned>(&self) -> Result<T> {
        let raw = self.get_raw().await?;
        Ok(serde_json::from_str(&raw)?)
    }
    
    /// Get the full response from the AWS lambda extension, including parameter type / version / ARN
    /// info.
    ///
    /// Rarely used, see [`Self::get_raw()`] and [`Self::get_typed()`] for ways to retrieve string
    /// and JSON parameters, respectively.
    pub async fn get_as_full_extension_response(&self) -> Result<ExtensionResponseParam> {
        self.connection.get_parameter(&self.query).await
    }
}

impl PartialEq for Parameter {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query
    }
}

impl Eq for Parameter {}

/// The response from the AWS Lambda extension when successfully queried for a paramater at
/// endpoint `/systemsmanager/parameters/get/?name=...`.
#[derive(Deserialize)]
pub struct ExtensionResponseParam {
    /// The parameter returned.
    #[serde(rename = "Parameter")]
    pub parameter: ExtensionResponseParameterField
}

/// A parameter returned by the AWS Lambda extension, as structured JSON
#[derive(Deserialize)]
pub struct ExtensionResponseParameterField {
    /// The parameter's ARN (Amazon Resource Name) full path.
    #[serde(rename = "ARN")]
    pub arn: String,
    /// The data type of the parameter (e.g. text)
    #[serde(rename = "DataType")]
    pub data_type: String,
    /// The date the parameter was last modified
    #[serde(rename = "LastModifiedDate")]
    pub last_modified_date: String,
    /// The parameter's name.
    #[serde(rename = "Name")]
    pub name: String,
    /// The date the parameter's type (e.g. `String`, `StringList`, or `SecureString`).
    #[serde(rename = "Type")]
    pub r#type: String,
    /// The value of the parameter (this is the field that gets returned by [`Parameter::get_raw()`]).
    #[serde(rename = "Value")]
    pub value: String,
    /// The date the parameter's version.
    #[serde(rename = "Version")]
    pub version: u64
}

/// A query for a specific [`Secret`] in AWS Secrets Manager. See [`Manager::get_secret`] for usage.
/// 
/// # Sealed
/// You cannot implement this trait yourself.
#[sealed]
pub trait Query {
    #[doc(hidden)]
    fn get_query_string(&self) -> String;
}

/// Flexible builder for a complex [`Query`].
#[must_use = "continue building a query with the `with_version_id` or `with_version_stage` method"]
pub struct QueryBuilder<'a> {
    secret_id: &'a str,
}

impl<'a> QueryBuilder<'a> {
    /// Create a new builder with the secret name or ARN.
    pub fn new(secret_id: &'a str) -> Self {
        Self { secret_id }
    }

    /// Create a query with a version id.
    pub fn with_version_id(self, version_id: &'a str) -> VersionIdQuery<'a> {
        VersionIdQuery {
            secret_id: self.secret_id,
            version_id,
        }
    }

    /// Create a query with a version stage.
    pub fn with_version_stage(self, version_stage: &'a str) -> VersionStageQuery<'a> {
        VersionStageQuery {
            secret_id: self.secret_id,
            version_stage,
        }
    }
}

/// Query by the secret name or ARN.
/// 
/// This returns the current value of the secret (stage = "AWSCURRENT") and is usually what you want to use.
/// 
/// Any string-like type can be used, including [`String`], [`&str`], and [`std::borrow::Cow<str>`].
/// 
/// ```rust
/// # use aws_parameters_and_secrets_lambda::ManagerBuilder;
/// # temp_env::with_var("AWS_SESSION_TOKEN", Some("xyz"), || {
/// # let manager = ManagerBuilder::new().build()?;
/// let secret = manager.get_secret("secret-name");
/// # Ok::<_, anyhow::Error>(())
/// # });
/// ```
#[sealed]
impl<T: AsRef<str>> Query for T {
    fn get_query_string(&self) -> String {
        format!("secretId={}", self.as_ref())
    }
}

/// A query for a secret with a version id. Create one via [`QueryBuilder::with_version_id`].
/// 
/// The version id is a unique identifier returned by Secrets Manager when a secret is created or updated.
#[derive(Debug, Clone)]
pub struct VersionIdQuery<'a> {
    secret_id: &'a str,
    version_id: &'a str,
}

/// Query by the version id of the secret as well as the secret name or ARN.
/// 
/// ```rust
/// # use aws_parameters_and_secrets_lambda::ManagerBuilder;
/// # temp_env::with_var("AWS_SESSION_TOKEN", Some("xyz"), || {
/// # let manager = ManagerBuilder::new().build()?;
/// use aws_parameters_and_secrets_lambda::QueryBuilder;
/// 
/// let query = QueryBuilder::new("secret-name")
///     .with_version_id("18b94218-543d-4d67-aec5-f8e6a41f7813");
/// let secret = manager.get_secret(query);
/// # Ok::<_, anyhow::Error>(())
/// # });
#[sealed]
impl Query for VersionIdQuery<'_> {
    fn get_query_string(&self) -> String {
        format!("secretId={}&versionId={}", self.secret_id, self.version_id)
    }
}

/// A query for a secret with a version stage. Create one via [`QueryBuilder::with_version_stage`].
/// 
/// The "AWSCURRENT" stage is the current value of the secret, while the "AWSPREVIOUS" stage is the last value of the "AWSCURRENT" stage.
/// You can also use your own stages.
#[derive(Debug, Clone)]
pub struct VersionStageQuery<'a> {
    secret_id: &'a str,
    version_stage: &'a str,
}

/// Query by the stage of the secret as well as the secret name or ARN.
/// 
/// ```rust
/// # use aws_parameters_and_secrets_lambda::ManagerBuilder;
/// # temp_env::with_var("AWS_SESSION_TOKEN", Some("xyz"), || {
/// # let manager = ManagerBuilder::new().build()?;
/// use aws_parameters_and_secrets_lambda::QueryBuilder;
/// 
/// let query = QueryBuilder::new("secret-name")
///     .with_version_stage("AWSPREVIOUS");
/// let secret = manager.get_secret(query);
/// # Ok::<_, anyhow::Error>(())
/// # });
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

    const SECRETS_ENDPOINT: &'static str = "/secretsmanager/get";
    const PARAMETERS_ENDPOINT: &'static str  = "/systemsmanager/parameters/get";

    struct MockServerConfig<'a> {
        endpoint: &'a str,
        query: HashMap<&'a str, &'a str>,
        status: u16,
        response: &'a str,
    }

    async fn with_mock_server<T: Future>(config: MockServerConfig<'_>, f: impl FnOnce(u16) -> T) {
        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            let mut when = when.method("GET").path(config.endpoint);

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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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
            endpoint: SECRETS_ENDPOINT,
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

    #[tokio::test]
    async fn test_manager_get_ssm_raw_parameter() {
        let config = MockServerConfig {
            endpoint: PARAMETERS_ENDPOINT,
            query: hashmap! {"name" => "/some/path/to/a/param", "withDecryption" => "false"},
            status: 200,
            response: "{
                \"Parameter\": {
                    \"ARN\": \"arn:aws:ssm:us-east-1:000000000000:parameter/some/path/to/a/param\",
                    \"DataType\": \"text\",
                    \"LastModifiedDate\": \"2024-03-01T17:53:36.314Z\",
                    \"Name\": \"/some/path/to/a/param\",
                    \"Selector\": null,
                    \"SourceResult\": null,
                    \"Type\": \"String\",
                    \"Value\": \"Some param\",
                    \"Version\": 1
                },
                \"ResultMetadata\": {}
            }",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let param_value = manager.get_parameter("/some/path/to/a/param", false).get_raw().await.unwrap();

            assert_eq!(String::from("Some param"), param_value);
        })
        .await;
    }

    #[tokio::test]
    async fn test_manager_get_ssm_raw_parameter_secure_string() {
        let config = MockServerConfig {
            endpoint: PARAMETERS_ENDPOINT,
            query: hashmap! {"name" => "/some/path/to/a/param", "withDecryption" => "true"},
            status: 200,
            response: "{
                \"Parameter\": {
                    \"ARN\": \"arn:aws:ssm:us-east-1:000000000000:parameter/some/path/to/a/param\",
                    \"DataType\": \"text\",
                    \"LastModifiedDate\": \"2024-03-01T17:53:36.314Z\",
                    \"Name\": \"/some/path/to/a/param\",
                    \"Selector\": null,
                    \"SourceResult\": null,
                    \"Type\": \"SecureString\",
                    \"Value\": \"Some encrypted string (now decrypted)\",
                    \"Version\": 1
                },
                \"ResultMetadata\": {}
            }",
        };

        with_mock_server(config, |port| async move {
            let manager = ManagerBuilder::new()
                .with_port(port)
                .with_token(String::from("TOKEN"))
                .build()
                .unwrap();

            let param_value = manager.get_parameter("/some/path/to/a/param", true).get_raw().await.unwrap();

            assert_eq!(String::from("Some encrypted string (now decrypted)"), param_value);
        })
        .await;
    }
}
