use deadpool_postgres::{Config, Pool, ManagerConfig, RecyclingMethod};
use tokio_postgres::Config as PgConfig;
use tokio_postgres_rustls::MakeRustlsConnect;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

pub async fn create_pool() -> Pool {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(&TLS_SERVER_ROOTS);

    let tls_config = Arc::new(ClientConfig::builder().with_safe_defaults().with_root_certificates(root_cert_store).with_no_client_auth());
    let rustls_connector = MakeRustlsConnect::new(tls_config);

    let mut pg_config = PgConfig::new();
    pg_config
        .host("localhost")
        .user("postgres")
        .password("mysecretpassword")
        .dbname("mydatabase");

    let pool_config = Config {
        manager: Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        }),
        ..Default::default()
    };

    pool_config.create_pool(Some(rustls_connector), tokio_postgres::NoTls).expect("Failed to create pool")
}
