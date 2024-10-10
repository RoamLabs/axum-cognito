mod cognito_auth_layer;
mod cognito_validator;
pub use cognito_auth_layer::CognitoAuthLayer;
pub use cognito_validator::{CognitoValidator, OAuthTokenType};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AxumCognitoError {
    #[error("Failed to build key set: `{0}`")]
    JsonwebtokensCognito(String),
    #[error(transparent)]
    Jsonwebtokens(#[from] jsonwebtokens::error::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::error::Error),
}
