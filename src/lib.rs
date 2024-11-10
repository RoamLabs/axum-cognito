//! axum-cognito is middleware for tower http, built specifically for axum that authroises users
//! using cognito pools
//!
//!
//! # Example
//! ```rust
//! let cognito_auth_layer: CognitoAuthLayer<UserClaims> = CognitoAuthLayer::new(
//!     OAuthTokenType::Id,
//!     &olaf_config.cognito_client_id,
//!     &olaf_config.cognito_pool_id,
//!     &olaf_config.cognito_region,
//! )
//! .await?;
//! ```
#![warn(clippy::pedantic)]
mod cognito_auth_layer;
mod cognito_validator;
pub use cognito_auth_layer::CognitoAuthLayer;
pub use cognito_validator::{CognitoValidator, OAuthTokenType};
use thiserror::Error;

/// Axum errors
#[derive(Error, Debug)]
pub enum AxumCognitoError {
    #[error("Failed to build key set: `{0}`")]
    JsonwebtokensCognito(String),
    #[error(transparent)]
    Jsonwebtokens(#[from] jsonwebtokens::error::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::error::Error),
}
