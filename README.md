# aws-parameters-and-secrets-lambda
Cache AWS Secrets Manager secrets in your AWS Lambda function, reducing latency (we don't need to query another service) and cost ([Secrets Manager charges based on queries]).

## Quickstart
Add the [AWS Parameters and Secrets Lambda Extension] [layer to your Lambda function]. Only version 2 of this layer is currently supported.

Assuming a secret exists with the name "backend-server" containing a key/value pair with a key of "api_key" and a value of
"dd96eeda-16d3-4c86-975f-4986e603ec8c" (our super secret API key to our backend), this code will get the secret from the cache, querying
Secrets Manager if it is not in the cache, and present it in a strongly-typed `BackendServer` object.

```rust
use aws_parameters_and_secrets_lambda::Manager;
use serde::Deserialize;

#[derive(Deserialize)]
struct BackendServer {
    api_key: String
}

let manager = Manager::default();
let secret = manager.get_secret("backend-server");
let secret_value: BackendServer = secret.get_typed().await?;
assert_eq!("dd96eeda-16d3-4c86-975f-4986e603ec8c", secret_value.api_key);
```

[Secrets Manager charges based on queries]: https://aws.amazon.com/secrets-manager/pricing/
[AWS Parameters and Secrets Lambda Extension]: https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html
[layer to your Lambda function]: https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html

## Documentation
Thorough documentation for this crate is available on [docs.rs](https://docs.rs/aws-parameters-and-secrets-lambda/).

## License
This crate is licensed under the MIT or Apache 2.0 license, at your option. 
