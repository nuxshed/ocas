use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// creates the connection pool and runs migrations
pub async fn initpool(dburl: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(dburl)
        .await
        .expect("failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");

    pool
}
