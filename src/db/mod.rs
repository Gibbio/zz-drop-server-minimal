use std::str::FromStr;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("connect: {0}")]
    Connect(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Wrapper around `SqlitePool`. We keep our own type so future tasks
/// can attach helpers (e.g. transaction builders) without leaking the
/// raw pool everywhere. For now it's a near-newtype.
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open `database_url`, run any pending migrations, return the
    /// pool. The reference implementation supports SQLite only — both
    /// `sqlite::memory:` for tests and `sqlite:./state.db` for
    /// development.
    ///
    /// We always set `create_if_missing(true)` so a fresh
    /// `DATABASE_URL=sqlite:./local-test.db` Just Works on the first
    /// run instead of failing with `SQLITE_CANTOPEN`.
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        let opts = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
