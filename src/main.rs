use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Json, Path},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::net::TcpListener;
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
struct User {
    id: i32,
    username: String,
    email: String,
    password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32,
    exp: usize,
}

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
    let password = payload.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(password, &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            error!("Failed to hash password: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let query = "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id";
    let user_id: i32 = match sqlx::query(query)
        .bind(&payload.username)
        .bind(&payload.email)
        .bind(&password_hash)
        .fetch_one(&pool)
        .await {
        Ok(row) => row.get(0),
        Err(e) => {
            error!("Failed to insert user: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    info!("User registered with id: {:?}", user_id);
    StatusCode::CREATED
}

async fn login_user(
    axum::Extension(pool): axum::Extension<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let query = "SELECT id, username, email, password_hash FROM users WHERE username = $1";
    let user = match sqlx::query_as::<_, User>(query)
        .bind(&payload.username)
        .fetch_one(&pool)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to parse password hash: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).is_ok() {
        let claims = Claims {
            sub: user.id,
            exp: 10000000000,
        };
        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("your_secret_key".as_ref())) {
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
    let query = "SELECT id, username, email, password_hash FROM users WHERE id = $1";
    let user = match sqlx::query_as::<_, User>(query)
        .bind(user_id)
        .fetch_one(&pool)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to fetch user: {}", e);
            return Err(StatusCode::NOT_FOUND);
        }
    };

    info!("Fetched user: {}", user.username);
    Ok(Json(user))
}
