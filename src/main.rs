mod cli;
mod client;
mod server;

#[tokio::main]
async fn main() {
    if let Err(err) = cli::run().await {
        eprintln!("{err}");
    }
}
