use axum::{
    Router,
    routing::post,
    http::StatusCode,
    response::IntoResponse,
    serve::Serve,  
};

use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

use std::error::Error;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ServeDir::new("assets")
            .not_found_service(ServeFile::new("assets/index.html"));
        let router = 
            Router::new()
                .fallback_service(assets_dir)
                .route("/signup", post(signup))
                .route("/login", post(login))
                .route("/logout", post(logout))
                .route("/verify-2fa", post(verify_2fa))
                .route("/verify-token", post(verify_token));

        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address, })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn verify_token() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
