//! Database seeding utilities.
//!
//! This module provides functions to seed the database with initial data,
//! such as creating the default admin user on first run.

use super::{create_user_repository, DbPool};
use crate::auth::{password::hash_password, Role, User};
use rand::Rng;
use tracing::{info, warn};

/// Ensures a default admin user exists in the database.
///
/// If no users exist, creates an admin user with:
/// - Username: `admin`
/// - Email: `admin@localhost`
/// - Password: from `TW_ADMIN_PASSWORD` env var, or randomly generated
/// - Role: Admin
///
/// # Returns
///
/// `Ok(Some(password))` if a new admin was created (password is the generated one)
/// `Ok(None)` if an admin already exists
/// `Err(...)` if there was an error
pub async fn ensure_admin_user(
    pool: &DbPool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let user_repo = create_user_repository(pool);

    // Check if any users exist
    if user_repo.any_exist().await? {
        info!("Users already exist, skipping admin seed");
        return Ok(None);
    }

    // Get password from environment or generate one
    let password = std::env::var("TW_ADMIN_PASSWORD").ok().unwrap_or_else(|| {
        let generated = generate_secure_password();
        warn!("No TW_ADMIN_PASSWORD set, generated random password");
        generated
    });

    // Hash the password
    let password_hash = hash_password(&password)?;

    // Create the admin user
    let admin = User::new("admin@localhost", "admin", password_hash, Role::Admin);

    user_repo.create(&admin).await?;

    info!("Created default admin user: admin");

    Ok(Some(password))
}

/// Generates a secure random password.
///
/// The password will be 16 characters with:
/// - Uppercase letters
/// - Lowercase letters
/// - Digits
/// - Special characters
fn generate_secure_password() -> String {
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*";

    let mut rng = rand::thread_rng();
    let mut password = Vec::with_capacity(16);

    // Ensure at least one of each type
    password.push(UPPER[rng.gen_range(0..UPPER.len())]);
    password.push(LOWER[rng.gen_range(0..LOWER.len())]);
    password.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
    password.push(SPECIAL[rng.gen_range(0..SPECIAL.len())]);

    // Fill the rest randomly from all characters
    let all: Vec<u8> = [UPPER, LOWER, DIGITS, SPECIAL].concat();
    for _ in 0..12 {
        password.push(all[rng.gen_range(0..all.len())]);
    }

    // Shuffle the password
    for i in (1..password.len()).rev() {
        let j = rng.gen_range(0..=i);
        password.swap(i, j);
    }

    String::from_utf8(password).expect("Generated password should be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::password::verify_password;

    #[test]
    fn test_generate_secure_password() {
        let password = generate_secure_password();

        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| "!@#$%^&*".contains(c)));
    }

    #[test]
    fn test_generated_password_is_hashable() {
        let password = generate_secure_password();
        let hash = hash_password(&password).unwrap();
        assert!(verify_password(&password, &hash).unwrap());
    }
}
