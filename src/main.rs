mod cli;
mod client;
mod server;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    if let Err(err) = cli::run().await {
        eprintln!("{err}");
    }
}
