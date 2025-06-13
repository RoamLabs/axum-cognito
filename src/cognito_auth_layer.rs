use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, extract::Request, response::Response};
use http::StatusCode;
use pin_project::pin_project;
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
    validator: Arc<CognitoValidator<UC>>,
}

impl<UC> CognitoAuthLayer<UC>
where
    UC: for<'de> serde::Deserialize<'de>,
{
    /// Create a layer directly from a validator
    #[must_use]
    pub fn from_validator(validator: CognitoValidator<UC>) -> Self {
        Self {
            validator: validator.into(),
        }
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
            .await?
            .into(),
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
    validator: Arc<CognitoValidator<UC>>,
}

impl<S, UC> Service<Request> for CognitoAuthMiddleware<S, UC>
where
    UC: for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + std::fmt::Debug,
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let validator = self.validator.clone();

        let (parts, body) = request.into_parts();
        let headers = &parts.headers;

        let Some(header_value) = headers.get("Authorization") else {
            return ResponseFuture::Failure {
                resp: create_bad_request_response,
                arg: "Missing 'Authorization' header",
            };
        };
        let Ok(raw_token) = header_value.to_str() else {
            return ResponseFuture::Failure {
                resp: create_bad_request_response,
                arg: "Malformed token",
            };
        };

        let token = raw_token["Bearer ".len()..].trim_start();
        let Ok(some_claims) = validator.try_validate_token(token) else {
            return ResponseFuture::Failure {
                resp: create_bad_request_response,
                arg: "Malformed token",
            };
        };

        let Some(user_claims) = some_claims else {
            return ResponseFuture::Failure {
                resp: create_unauthroised_response,
                arg: "No user claims",
            };
        };

        let mut request = Request::from_parts(parts, body);
        let extensions = request.extensions_mut();
        extensions.insert(user_claims);

        let response_future = self.inner.call(request);

        ResponseFuture::Success { response_future }
    }
}

#[pin_project(project = EnumProj)]
pub enum ResponseFuture<F> {
    Success {
        #[pin]
        response_future: F,
    },
    Failure {
        resp: fn(&'static str) -> Response,
        arg: &'static str,
    },
}

impl<F, Error> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response, Error>>,
{
    type Output = Result<Response, Error>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            EnumProj::Success { response_future } => {
                // First check if the response future is ready.
                match response_future.poll(cx) {
                    Poll::Ready(result) => {
                        // The inner service has a response ready for us or it has
                        // failed.
                        Poll::Ready(result)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            EnumProj::Failure { resp, arg } => {
                let response = resp(arg);
                Poll::Ready(Ok(response))
            }
        }
    }
}

fn create_bad_request_response(body_text: &'static str) -> Response {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    *response.body_mut() = Body::from(body_text);
    response
}

fn create_unauthroised_response(body_text: &'static str) -> Response {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    *response.body_mut() = Body::from(body_text);
    response
}
