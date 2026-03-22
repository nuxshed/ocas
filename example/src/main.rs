use axum::routing::get;
use axum::{Json, Router};
use ocas_auth::{Claims, Faculty, OcasClient, OcasConfig, Student};
use serde_json::{json, Value};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = OcasConfig::fromenv();
    let client = OcasClient::new(config).await;

    let app = Router::new()
        .nest("/auth", client.authrouter())
        .route("/me", get(me))
        .route("/student", get(studentonly))
        .route("/faculty", get(facultyonly))
        .route("/", get(home))
        .layer(axum::middleware::from_fn(ocas_auth::refresh::refreshmw))
        .layer(client.layer());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("testapp listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> axum::response::Html<&'static str> {
    axum::response::Html(
        r#"<h3>testapp</h3>
<a href="/auth/login">login with ocas</a> |
<a href="/me">/me</a> |
<a href="/student">/student</a> |
<a href="/faculty">/faculty</a> |
<a href="/auth/logout">logout</a>"#,
    )
}

async fn me(claims: Claims) -> Json<Value> {
    Json(json!({
        "sub": claims.sub,
        "email": claims.email,
        "type": claims.r#type,
        "rollnum": claims.rollnum,
        "batch": claims.batch,
        "branch": claims.branch,
    }))
}

async fn studentonly(caller: Student) -> Json<Value> {
    Json(json!({
        "msg": "students only",
        "email": caller.email,
    }))
}

async fn facultyonly(caller: Faculty) -> Json<Value> {
    Json(json!({
        "msg": "faculty only",
        "email": caller.email,
    }))
}
