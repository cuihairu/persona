use persona_ssh_agent::run_agent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_agent().await
}
