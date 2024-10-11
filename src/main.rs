use actix_web::{get, post, web, App, HttpServer, HttpResponse, HttpRequest, Result};
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error as JwtError};
use std::time::{SystemTime, UNIX_EPOCH};
use deadpool_postgres::{Client, Pool};
mod db;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,       // Subject (user id or email)
    exp: usize,        // Expiration time (as timestamp)
}

// Secret key to sign tokens (in a real app, you would store this securely)
const SECRET_KEY: &[u8] = b"mysecret";

//TOKEN GEN
fn generate_jwt(user_id: &str) -> Result<String, JwtError> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize + 3600; // Token expires in 1 hour

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY))
}

//TOKEN VERIF
fn verify_jwt(token: &str) -> Result<Claims, JwtError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims) // Extract the claims from the token
}

//MIDDLEWARE
async fn auth_middleware(req: HttpRequest) -> Result<HttpResponse> {
    if let Some(auth_header) = req.headers().get("Authorization") {
        let auth_header = auth_header.to_str().unwrap_or("");

        if auth_header.starts_with("Bearer ") {
            let token = auth_header.trim_start_matches("Bearer ");

            match verify_jwt(token) {
                Ok(claims) => {
                    println!("Authenticated user: {}", claims.sub);
                    return Ok(HttpResponse::Ok().body(format!("Welcome, {}!", claims.sub)));
                }
                Err(_) => {
                    return Ok(HttpResponse::Unauthorized().body("Invalid or expired token."));
                }
            }
        }
    }
    Ok(HttpResponse::Unauthorized().body("Authorization token required"))
}

//ROUTES
#[post("/login")]
async fn login() -> HttpResponse {
    let user_id = "user123";

    match generate_jwt(user_id) {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "token": token })),
        Err(_) => HttpResponse::InternalServerError().body("Error generating token"),
    }
}

#[get("/products")]
async fn get_products(pool: web::Data<Pool>) -> Result<HttpResponse> {
    let client: Client = pool.get().await.expect("Error connecting to DB");
    let statement = client.prepare("SELECT * FROM products").await.expect("Error preparing statement");
    let rows = client.query(&statement, &[]).await.expect("Error fetching products");

    let products: Vec<_> = rows.into_iter().map(|row| {
        serde_json::json!({
            "ean": row.get::<_, String>(0),
            "description": row.get::<_, String>(1),
            "categories_da": row.get::<_, String>(2),
            "categories_en": row.get::<_, String>(3),
            "image": row.get::<_, String>(4),
        })
    }).collect();

    Ok(HttpResponse::Ok().json(products))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = db::create_pool().await;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(login)
            .service(get_products)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
