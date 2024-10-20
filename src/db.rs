use serde::{Deserialize, Serialize};
use sqlx::{Execute, PgPool};
use sqlx::Error;
use sqlx::Row;


#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
}
pub async fn create_user(pool: &PgPool, username: &str, email: &str, password_hash: &str) -> Result<i32, Error> {
    let query = "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id";
    let row = sqlx::query(query)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;
    Ok(row.get(0))
}

pub async fn fetch_user_by_username(pool: &PgPool, username: &str) -> Result<User, Error> {
    let query = "SELECT id, username, email, password_hash FROM users WHERE username = $1";
    let user = sqlx::query_as::<_, User>(query)
        .bind(username)
        .fetch_one(pool)
        .await?;
    Ok(user)
}

pub async fn fetch_user_by_id(pool: &PgPool, user_id: i32) -> Result<User, Error> {
    let query = "SELECT id, username, email, password_hash FROM users WHERE id = $1";
    let user = sqlx::query_as::<_, User>(query)
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(user)
}

pub async fn store_token(pool: &PgPool, user_id: i32, token: &str) -> Result<(), Error> {
    let query = "INSERT INTO tokens (user_id, token) VALUES ($1, $2)";
    sqlx::query(query)
        .bind(user_id)
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn verify_token(pool: &PgPool, token: &str, user_id: i32) -> Result<(), Error> {
    let query = sqlx::query("SELECT token FROM tokens WHERE user_id = $1 AND token = $2")
        .bind(user_id)
        .bind(token);

    println!("user_id: {}", user_id);
    println!("token: {}", token);
    println!("Executing SQL query: {:?}", query.sql());

    let _ = query.fetch_one(pool).await?;
    Ok(())
}