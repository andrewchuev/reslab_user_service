
# User Service REST API

This project is a REST API for managing user authentication and registration, built using Rust with Axum as the web framework and SQLx for database interactions. The service includes user registration, login, and secure data access through token-based authentication.

## Features

- **User Registration**: Allows new users to register with a username, email, and password.
- **User Login**: Users can log in with their credentials, and a JWT token is generated upon successful authentication.
- **Secure User Data Retrieval**: Protects user data by requiring a valid token for access.
- **Password Hashing**: Uses Argon2 for secure password hashing before storing passwords in the database.
- **Token Management**: Generates JWT tokens for authenticated sessions and stores them in a database for validation.

## Dependencies

- **Axum**: Web framework for building HTTP services.
- **SQLx**: Asynchronous database connection pool and query tool for PostgreSQL.
- **Argon2**: Secure password hashing algorithm.
- **Jsonwebtoken**: Library for creating and verifying JWT tokens.
- **Tracing**: For logging and debugging.
- **Dotenv**: For managing environment variables.

## Endpoints

### 1. `/api/register` [POST]
Registers a new user with the following payload:

```json
{
  "username": "example_user",
  "email": "user@example.com",
  "password": "your_password"
}
```

Upon successful registration, a JWT token is generated and stored for future validation.

### 2. `/api/login` [POST]
Authenticates a user and provides a JWT token for authenticated sessions. Payload:

```json
{
  "username": "example_user",
  "password": "your_password"
}
```

Returns:

```json
{
  "token": "your_jwt_token"
}
```

### 3. `/api/users/:id` [GET]
Retrieves user information for a specific user ID. Requires an `Authorization` header with a valid JWT token.

**Headers**:

```
Authorization: Bearer your_jwt_token
```

## Project Structure

- **`main.rs`**: Contains the entry point for the application, including route definitions.
- **`db.rs`**: Manages all database-related operations, such as creating users, storing tokens, and verifying tokens.
- **`auth.rs`**: Handles password hashing, password verification, and JWT token generation.

## How to Run

1. **Clone the Repository**
   ```sh
   git clone https://github.com/andrewchuev/reslab_user_service.git
   cd reslab_user_service
   ```

2. **Set Up Environment Variables**
   Create a `.env` file in the project root with the following content:
   ```env
   DATABASE_URL=postgres://user:password@localhost/user_db
   ```

3. **Build and Run**
   ```sh
   cargo build
   cargo run
   ```

## Security Considerations

- **Password Hashing**: All passwords are hashed using Argon2 before storing in the database to ensure that they are not stored in plaintext.
- **Token Storage**: JWT tokens are stored in a separate `tokens` table for validation during protected resource access.
- **Secure Routes**: Access to user data (`/api/users/:id`) is protected by requiring a valid JWT token.

## Future Improvements

- **Token Expiry**: Implement token expiry and refresh mechanisms to enhance security.
- **Role-Based Access Control**: Add different user roles (e.g., admin, regular user) to provide differentiated access to resources.
- **Rate Limiting**: Introduce rate limiting to prevent brute-force attacks and enhance the stability of the service.
