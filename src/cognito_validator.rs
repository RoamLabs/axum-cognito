use std::marker::PhantomData;

use crate::AxumCognitoError;
use jsonwebtokens as jwt;
use jsonwebtokens_cognito::KeySet;

#[derive(Copy, Clone)]
pub enum OAuthTokenType {
    Id,
    Access,
}

/// Validator for JWT tokens issued by Cognito
#[derive(Clone)]
pub struct CognitoValidator<UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    key_set: KeySet,
    token_verifier: jwt::Verifier,
    phantom_data: PhantomData<UC>,
}

impl<UC> CognitoValidator<UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    /// Create a new `CognitoValidator`.
    ///
    /// # Arguments
    /// * `token_type` - type of token to validate TODO: add docs link for the types of token
    /// * `cognito_client_id` - client id for your Cognito client
    /// * `cognito_pool_id` - pool id for your Cognito pool
    /// * `cognito_region` - AWS region your Cognito pool is in
    ///
    ///
    /// # Returns
    /// New CognitoValidator
    ///
    /// # Errors
    /// Returns an error if the CognitoValidator cannot be created
    pub async fn new(
        token_type: OAuthTokenType,
        cognito_client_id: &str,
        cognito_pool_id: &str,
        cognito_region: &str,
    ) -> Result<Self, AxumCognitoError> {
        let key_set = KeySet::new(cognito_region, cognito_pool_id)
            .map_err(|error| AxumCognitoError::JsonwebtokensCognito(error.to_string()))?;
        key_set
            .prefetch_jwks()
            .await
            .map_err(|error| AxumCognitoError::JsonwebtokensCognito(error.to_string()))?;

        let token_verifier = match token_type {
            OAuthTokenType::Id => key_set
                .new_id_token_verifier(&[cognito_client_id])
                .build()?,
            OAuthTokenType::Access => key_set
                .new_access_token_verifier(&[cognito_client_id])
                .build()?,
        };

        Ok(Self {
            key_set,
            token_verifier,
            phantom_data: PhantomData,
        })
    }

    /// Validate a token and return the user claims
    ///
    /// # Arguments
    /// * `token` - token to validate
    ///
    /// # Returns
    /// User claims extracted from the provided token
    ///
    /// # Errors
    /// returns and error if the user claims cannot be deserialized
    pub async fn validate_token(&self, token: &str) -> Result<Option<UC>, AxumCognitoError> {
        let verification = self.key_set.verify(token, &self.token_verifier).await;
        if let Ok(claims) = verification {
            let user_claims: UC = serde_json::from_value(claims)?;
            Ok(Some(user_claims))
        } else {
            Ok(None)
        }
    }
}
