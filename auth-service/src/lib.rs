use axum::{
    Router,
    routing::post,
    serve::Serve,  
};

use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

use std::error::Error;

pub mod app_state;
use app_state::AppState;

pub mod domain;

pub mod routes;
use routes::*;

pub mod services;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ServeDir::new("assets")
            .not_found_service(ServeFile::new("assets/index.html"));

        let router = 
            Router::new()
                .fallback_service(assets_dir)
                .route("/signup", post(signup))
                .route("/login", post(login))
                .route("/verify-2fa", post(verify_2fa))
                .route("/logout", post(logout))
                .route("/verify-token", post(verify_token))
                .with_state(app_state);

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
