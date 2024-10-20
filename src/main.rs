mod db;
mod auth;

use crate::db::{store_token, verify_token, User};
use auth::{create_jwt, hash_password, verify_password};


use axum::routing::patch;
use axum::{extract::{Json, Path}, http::StatusCode, routing::{get, post}, Extension, Router};
use axum_extra::TypedHeader;
use db::{create_user, fetch_user_by_id, fetch_user_by_username};
use dotenv::dotenv;
use headers::authorization::Bearer;
use headers::Authorization;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;
use tracing::{error, info};

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
        .route("/api/users/:id", patch(update_user))
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
            let token = match create_jwt(user_id) {
                Ok(token) => token,
                Err(e) => {
                    error!("Failed to create token: {}", e);
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            };

            if let Err(e) = store_token(&pool, user_id, &token).await {
                error!("Failed to store token: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }

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
    TypedHeader(Authorization(token)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<User>, StatusCode> {
    println!("token: {}", token.token());

    if let Err(e) = verify_token(&pool, token.token(), user_id).await {
        error!("Invalid token: {}", e);
        return Err(StatusCode::UNAUTHORIZED);
    }

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

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    username: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

async fn update_user(
    Extension(pool): Extension<PgPool>,
    Path(user_id): Path<i32>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut transaction = pool.begin().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(username) = payload.username {
        sqlx::query!(
            "UPDATE users SET username = $1 WHERE id = $2",
            username,
            user_id
        ).execute(&mut *transaction)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(email) = payload.email {
        sqlx::query!(
            "UPDATE users SET email = $1 WHERE id = $2",
            email,
            user_id
        )
            .execute(&mut *transaction)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(password) = payload.password {
        let password_hash = hash_password(&password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            password_hash,
            user_id
        )
            .execute(&mut *transaction)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    transaction.commit().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

// Adding the route for the new update user functionality
