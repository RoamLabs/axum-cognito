use std::task::{Context, Poll};

use axum::{body::Body, extract::Request, response::Response};
use futures_util::future::BoxFuture;
use http::StatusCode;
use tower::{Layer, Service};

use crate::{AxumCognitoError, CognitoValidator, OAuthTokenType};

/// Layer for authorising routes using AWS Cognito
///
/// This layer uses the `Authorization` header. The header is decoded and the User Claims extracted
#[derive(Clone)]
pub struct CognitoAuthLayer<UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    validator: CognitoValidator<UC>,
}

impl<UC> CognitoAuthLayer<UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    /// Create a layer directly from a validator
    #[must_use]
    pub fn from_validator(validator: CognitoValidator<UC>) -> Self {
        Self { validator }
    }

    /// Create a layer
    ///
    /// # Arguments
    /// * `token_type` - type of token to validate, one of `ID` or `Access`
    /// * `cognito_client_id` - client id of the Cognito client
    /// * `cognito_pool_id` - pool id for the Cognito pool
    /// * `cognito_region` - AWS region of the Cognito pool
    ///
    /// # Returns
    /// a new `CognitoAuthLayer`
    ///
    /// # Errors
    /// Returns an `AxumCognitoError` if the construction of the validator fails
    pub async fn new(
        token_type: OAuthTokenType,
        cognito_client_id: &str,
        cognito_pool_id: &str,
        cognito_region: &str,
    ) -> Result<Self, AxumCognitoError> {
        Ok(Self {
            validator: CognitoValidator::new(
                token_type,
                cognito_client_id,
                cognito_pool_id,
                cognito_region,
            )
            .await?,
        })
    }
}

impl<S, UC> Layer<S> for CognitoAuthLayer<UC>
where
    UC: for<'de> serde::Deserialize<'de> + Clone,
{
    type Service = CognitoAuthMiddleware<S, UC>;
    fn layer(&self, inner: S) -> Self::Service {
        CognitoAuthMiddleware {
            inner,
            validator: self.validator.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CognitoAuthMiddleware<S, UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    inner: S,
    validator: CognitoValidator<UC>,
}

impl<S, UC> Service<Request<Body>> for CognitoAuthMiddleware<S, UC>
where
    UC: for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + std::fmt::Debug,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let validator = self.validator.clone();

        // see here for why and how to clone the inner service
        // https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let headers = &parts.headers;

            let Some(header_value) = headers.get("Authorization") else {
                let response = create_bad_request_response("Missing 'Authorization' header");
                return Ok(response);
            };

            let Ok(raw_token) = header_value.to_str() else {
                let response = create_bad_request_response("Malformed token");
                return Ok(response);
            };

            let token = raw_token["Bearer ".len()..].trim_start();

            let Ok(some_claims) = validator.validate_token(token).await else {
                let response = create_bad_request_response("Missing 'Authorization' header");
                return Ok(response);
            };

            let Some(user_claims) = some_claims else {
                let mut response = Response::default();
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                return Ok(response);
            };

            let mut request = Request::from_parts(parts, body);

            let extensions = request.extensions_mut();
            extensions.insert(user_claims);

            let response = inner.call(request).await?;
            Ok(response)
        })
    }
}

fn create_bad_request_response(body_text: &'static str) -> Response {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    *response.body_mut() = Body::from(body_text);
    response
}
