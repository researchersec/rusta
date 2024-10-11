use deadpool_postgres::{Config, Pool, ManagerConfig, RecyclingMethod};
use tokio_postgres_rustls::MakeRustlsConnect;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

pub async fn create_pool() -> Pool {
    let mut root_cert_store = RootCertStore::empty();
    let trust_anchors: Vec<OwnedTrustAnchor> = TLS_SERVER_ROOTS
        .iter()
        .map(|ta| OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        ))
        .collect();
    root_cert_store.add_server_trust_anchors(trust_anchors.into_iter());

    let tls_config = Arc::new(ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth());

    let rustls_connector = MakeRustlsConnect::new((*tls_config).clone());

    let mut pg_config = tokio_postgres::Config::new();
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

    pool_config.create_pool(rustls_connector).expect("Failed to create pool")
}
