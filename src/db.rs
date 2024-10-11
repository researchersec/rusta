use deadpool_postgres::{Config, Pool, ManagerConfig, RecyclingMethod};
use tokio_postgres_rustls::MakeRustlsConnect;
use rustls::{ClientConfig, RootCertStore, OwnedTrustAnchor};
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

pub async fn create_pool() -> Pool {
    // Setup RootCertStore for TLS
    let mut root_cert_store = RootCertStore::empty();
    let trust_anchors: Vec<OwnedTrustAnchor> = TLS_SERVER_ROOTS
        .0
        .iter()
        .map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
        })
        .collect();
    root_cert_store.add_server_trust_anchors(trust_anchors.into_iter());

    // Create TLS config
    let tls_config = Arc::new(ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth());

    // Create Rustls connector
    let rustls_connector = MakeRustlsConnect::new((*tls_config).clone());

    // Setup Postgres config
    let mut pg_config = tokio_postgres::Config::new();
    pg_config
        .host("localhost")
        .user("postgres")
        .password("mysecretpassword")
        .dbname("mydatabase");

    // Create pool configuration
    let pool_config = Config {
        manager: Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        }),
        ..Default::default()
    };

    // Create the connection pool with TLS
    pool_config.create_pool(rustls_connector).expect("Failed to create pool")
}
