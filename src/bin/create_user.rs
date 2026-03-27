use argon2::{
    Argon2,
    PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use sqlx::PgPool;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: create_user <username> <password>");
        std::process::exit(1);
    }

    let username = &args[1];
    let password = &args[2];

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        username,
        hash,
    )
    .execute(&pool)
    .await
    .expect("Failed to insert user");

    println!("User '{}' created successfully.", username);
}