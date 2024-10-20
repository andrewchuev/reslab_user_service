mod db;
mod auth;

use axum::{
    extract::{Json, Path},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;
use tracing::{info, error};
use db::{create_user, fetch_user_by_id, fetch_user_by_username};
use auth::{hash_password, verify_password, create_jwt};
use crate::db::User;

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    info!("🌟 REST API User Service 🌟");

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    let app = Router::new()
        .route("/api/register", post(register_user))
        .route("/api/login", post(login_user))
        .route("/api/users/:id", get(get_user))
        .layer(axum::Extension(pool));

    info!("✅ Server started successfully at 192.168.88.7:8080");

    let listener = TcpListener::bind("192.168.88.7:8080").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn register_user(
    axum::Extension(pool): axum::Extension<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> StatusCode {
    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to hash password: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    match create_user(&pool, &payload.username, &payload.email, &password_hash).await {
        Ok(user_id) => {
            info!("User registered with id: {}", user_id);
            StatusCode::CREATED
        }
        Err(e) => {
            error!("Failed to insert user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn login_user(
    axum::Extension(pool): axum::Extension<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let user = match fetch_user_by_username(&pool, &payload.username).await {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if verify_password(&payload.password, &user.password_hash).is_ok() {
        let token = match create_jwt(user.id) {
            Ok(token) => token,
            Err(e) => {
                error!("Failed to create token: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        info!("User logged in: {}", user.username);
        Ok(Json(LoginResponse { token }))
    } else {
        error!("Invalid password for user: {}", user.username);
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn get_user(
    axum::Extension(pool): axum::Extension<PgPool>,
    Path(user_id): Path<i32>,
) -> Result<Json<User>, StatusCode> {
    let user = match fetch_user_by_id(&pool, user_id).await {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            return Err(StatusCode::NOT_FOUND);
        }
    };

    info!("Fetched user: {}", user.username);
    Ok(Json(user))
}





