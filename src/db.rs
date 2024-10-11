use std::sync::Arc;
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use webpki::TrustAnchor;
use webpki_roots::TLS_SERVER_ROOTS;
use tokio_postgres_rustls::MakeRustlsConnect;
use deadpool_postgres::{Config, Pool};
use std::error::Error;

pub fn create_pool() -> Result<Pool, Box<dyn Error>> {
    // Load root certificates
    let mut root_cert_store = RootCertStore::empty();
    let trust_anchors: Vec<TrustAnchor> = TLS_SERVER_ROOTS.0.iter().copied().collect();
    root_cert_store.add_server_trust_anchors(trust_anchors.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    // Load client certificate and private key
    let mut cert_file = BufReader::new(File::open("client.crt")?);
    let mut key_file = BufReader::new(File::open("client.key")?);
    let cert_chain = certs(&mut cert_file)?.into_iter().map(rustls::Certificate).collect();
    let mut keys = pkcs8_private_keys(&mut key_file)?;
    let key = rustls::PrivateKey(keys.remove(0));

    // Build the TLS client configuration
    let mut tls_config = ClientConfig::new();
    tls_config.root_store = root_cert_store;
    tls_config.set_single_client_cert(cert_chain, key)?;
    let tls_config = Arc::new(tls_config);

    // Create Rustls connector
    let rustls_connector = MakeRustlsConnect::new((*tls_config).clone());

    // Configure Deadpool Postgres
    let mut pool_config = Config::new();
    pool_config.dbname = Some("my_database".to_string());
    pool_config.host = Some("localhost".to_string());
    pool_config.user = Some("my_user".to_string());
    pool_config.password = Some("my_password".to_string());

    // Create and return the connection pool
    let pool = pool_config.create_pool(Some(rustls_connector))?;
    Ok(pool)
}
