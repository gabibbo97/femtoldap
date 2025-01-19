mod commands;
mod ldap;

use clap::Parser;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Start the femtoLDAP server
    Server(commands::ServerArgs),
}

#[derive(clap::Parser, Debug)]
/// A microscopic stateless LDAP directory simulator
pub struct Args {
    /// Enable JSON logging
    #[arg(long, env)] pub log_json: bool,

    /// Enable verbose logging
    #[arg(short = 'v', long, env)] pub log_verbose: bool,

    /// Run on the single core runtime (reduced memory footprint)
    #[arg(long, env)] pub single_core: bool,

    #[command(subcommand)]
    pub command: Command,
}

fn main() -> anyhow::Result<()> {
    // cli args
    let args = Args::parse();

    // logging setup
    let mut logger = tracing_subscriber::fmt();
    if args.log_verbose {
        logger = logger.with_max_level(tracing::Level::DEBUG);
    } else {
        logger = logger.with_max_level(tracing::Level::INFO);
    }
    if args.log_json {
        logger.json().flatten_event(true).init();
    } else {
        logger.with_file(true).with_line_number(true).init();
    }
    tracing::debug!(cli_args = ?args);

    // create runtime
    let runtime = if args.single_core {
        tracing::info!("Using the single core runtime");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
    };

    // dispatch to the correct main
    runtime.block_on(async move {
        match args.command {
            Command::Server(server_args) => commands::main_server(server_args).await,
        }
    })
}
