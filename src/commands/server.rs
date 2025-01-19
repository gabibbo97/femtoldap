use std::sync::Arc;

use metrics::{counter, describe_counter};
use metrics_exporter_prometheus::PrometheusBuilder;
use rustls::pki_types::pem::PemObject;
use tokio_util::sync::CancellationToken;

use crate::ldap::{config::Config, database::LDAPReadOnlyInMemoryDatabase, server::ClientHandler, traits::Mergeable};

#[derive(clap::Args, Debug)]
pub struct ServerArgs {
    /// Path to the config file
    #[arg(short, long, default_value = "config.toml", env)] config_file: std::path::PathBuf,

    /// Path to a configuration directory with multiple configs in it
    #[arg(long, env)] config_dir: Option<std::path::PathBuf>,

    /// Bind address for the LDAP socket
    #[arg(long, default_value = "0.0.0.0:3389", env)] ldap_bind_addr: Option<String>,

    /// Bind address for the LDAPS socket
    #[arg(long, requires = "ldaps_certificate_file", requires = "ldaps_key_file", env)] ldaps_bind_addr: Option<String>,

    /// TLS certificate file path
    #[arg(long, env)] ldaps_certificate_file: Option<std::path::PathBuf>,

    /// TLS key file path
    #[arg(long, env)] ldaps_key_file: Option<std::path::PathBuf>,

    /// Prometheus metrics endpoint
    #[arg(long, default_value = "127.0.0.1:9000", env)] metrics_bind_addr: Option<String>,
}

enum LDAPListenerType {
    Plain,
    Tls {
        cert_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    }
}
impl LDAPListenerType {
    pub const fn protocol_name(&self) -> &'static str {
        match self {
            Self::Plain => "LDAP",
            Self::Tls { .. } => "LDAPS",
        }
    }
}

#[tracing::instrument(skip_all)]
async fn listen(
    addr: impl tokio::net::ToSocketAddrs,
    mut database_rx: tokio::sync::watch::Receiver<Arc<LDAPReadOnlyInMemoryDatabase>>,
    cancellation_token: CancellationToken,
    listener_type: LDAPListenerType,
) -> anyhow::Result<()> {
    // get initial database instance
    let mut database = database_rx.borrow().clone();

    // prepare task joinset
    let mut tasks = tokio::task::JoinSet::new();

    // create TLS acceptor
    let tls_acceptor = match &listener_type {
        LDAPListenerType::Plain => None,
        LDAPListenerType::Tls { cert_path, key_path } => {
            // parse certificate and key material
            let tls_cert = tokio::fs::read(cert_path).await?;
            let tls_cert = rustls::pki_types::CertificateDer::from_pem_slice(&tls_cert)?;
            let tls_key = tokio::fs::read(key_path).await?;
            let tls_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&tls_key)?;

            // prepare TLS config
            let tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![tls_cert], tls_key)?;

            // accept TLS connections
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

            Some(tls_acceptor)
        }
    };

    // start listening
    let sock = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(protocol = listener_type.protocol_name(), "Listening");
    loop {
        tokio::select! {
            biased;
            _ = cancellation_token.cancelled() => {
                tracing::debug!("Terminating");
                break;
            }
            r = database_rx.changed() => {
                let _ = r?;
                database = database_rx.borrow().clone();
                tracing::info!("Reloaded database");
            }
            r = tasks.join_next(), if !tasks.is_empty() => {
                let r = r.expect("Task set is empty");
                let r = r.expect("Failed getting result out of task");
                if let Err(error) = r {
                    tracing::error!(?error, "Error while handling connection");
                }
            }
            r = sock.accept() => {
                match r {
                    Ok((conn, addr)) => {
                        let connection_counter = counter!("femtoldap_connections_total", "protocol" => listener_type.protocol_name());
                        let database = database.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        tasks.spawn(async move {
                            if let Some(tls_acceptor) = tls_acceptor {
                                // handle TLS upgrade
                                let conn = tls_acceptor.accept(conn).await
                                    .inspect_err(|err| tracing::error!(error = ?err, "Error in accepting TLS connection"))?;
                                connection_counter.increment(1);
                                let mut handler = ClientHandler::new(conn, addr, database);
                                handler.handle_connection().await
                            } else {
                                // serve over plain TCP
                                connection_counter.increment(1);
                                let mut handler = ClientHandler::new(conn, addr, database);
                                handler.handle_connection().await
                            }
                        });
                    },
                    Err(error) => {
                        tracing::error!(?error, "Error in accepting connection");
                    }
                }
            }
        }
    }

    // join all pending tasks
    while let Some(res) = tasks.join_next().await {
        let res = res.expect("Failed getting task result");
        if let Err(error) = res {
            tracing::error!(?error, "Error while handling connection");
        }
    }

    Ok(())
}

#[tracing::instrument(skip_all, level = tracing::Level::DEBUG, ret)]
async fn load_configuration(args: &ServerArgs) -> anyhow::Result<Config> {
    let mut config = toml::from_str::<Config>(&tokio::fs::read_to_string(&args.config_file).await?)?;
    if let Some(config_dir) = &args.config_dir {
        let mut dir_reader = tokio::fs::read_dir(config_dir).await?;
        while let Some(entry) = dir_reader.next_entry().await? {
            if ! entry.file_name().to_string_lossy().ends_with(".toml") {
                continue;
            }
            if entry.path() == args.config_file {
                continue;
            }
            let extra_config = toml::from_str::<Config>(&tokio::fs::read_to_string(&entry.path()).await?)?;
            config.merge(extra_config);
            tracing::debug!(name = ?entry.path(), "Loaded extra config file");
        }
    }
    Ok(config)
}

#[tracing::instrument(skip_all, level = tracing::Level::DEBUG, ret)]
async fn create_database_from_config(config: &Config) -> Arc<LDAPReadOnlyInMemoryDatabase> {
    LDAPReadOnlyInMemoryDatabase::from_entries(config.assemble_entries()).into()
}

pub async fn main_server(args: ServerArgs) -> anyhow::Result<()> {
    // load configuration
    let config = load_configuration(&args).await?;

    // load database
    let database = create_database_from_config(&config).await;

    // database watch channel
    let (database_tx, database_rx) = tokio::sync::watch::channel(database.clone());

    // spawn tasks
    let cancellation_token = CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();

    if let Some(addr) = &args.ldap_bind_addr {
        tasks.spawn(listen(addr.clone(), database_rx.clone(), cancellation_token.clone(), LDAPListenerType::Plain));
    }
    if let (Some(addr), Some(tls_cert_path), Some(tls_key_path)) = (&args.ldaps_bind_addr, &args.ldaps_certificate_file, &args.ldaps_key_file) {
        tasks.spawn(listen(addr.clone(), database_rx.clone(), cancellation_token.clone(), LDAPListenerType::Tls { cert_path: tls_cert_path.clone(), key_path: tls_key_path.clone() }));
    }
    if let Some(addr) = &args.metrics_bind_addr {
        PrometheusBuilder::new()
            .with_http_listener(tokio::net::lookup_host(addr).await?.next().unwrap())
            .set_enable_unit_suffix(true)
            .install()?;
        // metrics
        describe_counter!("femtoldap_connections_total", metrics::Unit::Count, "Total number of connections");
        describe_counter!("femtoldap_successful_binds_total", metrics::Unit::Count, "Total number of successful bind requests");
        describe_counter!("femtoldap_failed_binds_total", metrics::Unit::Count, "Total number of failed bind requests");
        describe_counter!("femtoldap_requests_total", metrics::Unit::Count, "Total number of requests");
    }

    // wait for signal
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        tokio::select! {
            _ = sighup.recv() => {
                tracing::info!("Starting database reload");
                // load configuration
                let config = load_configuration(&args).await?;
                // load database
                let database = create_database_from_config(&config).await;
                // update config
                database_tx.send(database)?;
                tracing::info!("Loaded new database");
            }
            _ = sigterm.recv() => {
                cancellation_token.cancel();
                break;
            }
            _ = sigint.recv() => {
                cancellation_token.cancel();
                break;
            }
            r = tasks.join_next() => {
                let r = r.expect("No tasks in join set");
                let r = r.expect("Failed getting task result");
                if let Err(error) = r {
                    tracing::error!(?error, "Subtask failed");
                }
                cancellation_token.cancel();
                break;
            }
        }
    }
    tracing::info!("Terminating");

    // wait for tasks
    while let Some(res) = tasks.join_next().await {
        let res = res.expect("Failed getting task result");
        if let Err(error) = res {
            tracing::error!(?error, "Subtask failed");
        }
    }

    // done
    Ok(())
}
