mod bolt_8;

use clap::Parser;
use color_eyre::eyre;
use secp256k1::{PublicKey, SecretKey};
use std::process::ExitCode;
use tokio::{
    net::TcpStream,
    time::{timeout, Duration},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The address of the remote node in the following form: <public_key>@<ip>:<port>
    ///
    /// Note: Any public node should work.
    ///       Public nodes can be found at https://1ml.com/
    #[arg(short, long)]
    node_address: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if let Err(e) = perform_handshake(args).await {
        println!("{e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

async fn perform_handshake(args: Args) -> Result<(), eyre::Report> {
    let (rs_pk, address) = args.node_address.split_once('@').ok_or_else(|| {
        eyre::eyre!("Invalid node address. Expected format: <public_key>@<ip>:<port>")
    })?;

    let rs_pk = hex::decode(rs_pk)
        .map_err(|_e| eyre::eyre!("The provided node public key is not valid."))?;

    let rs_pk = PublicKey::from_slice(&rs_pk)
        .map_err(|_e| eyre::eyre!("The provided node public key is not valid."))?;

    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(address))
        .await
        .map_err(|_e| eyre::eyre!("Unable to connect to the remote node."))?
        .map_err(|e| eyre::eyre!("Unable to connect to the remote node: {e}"))?;

    let client_proto = bolt_8::protocol::ClientProtocol::new(rs_pk);

    let ls_sk = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let client_proto = client_proto
        .next(ls_sk)
        .map_err(|e| eyre::eyre!("Failed to perform handshake: {e}"))?;

    client_proto
        .send_message(&mut stream)
        .await
        .map_err(|e| eyre::eyre!("Failed to send hanshake message to remote node: {e}"))?;

    let client_proto = client_proto
        .next(&mut stream)
        .await
        .map_err(|e| eyre::eyre!("Failed to perform handshake: {e}"))?;

    let client_proto = client_proto
        .next()
        .map_err(|e| eyre::eyre!("Failed to perform handshake: {e}"))?;

    client_proto
        .send_message(&mut stream)
        .await
        .map_err(|e| eyre::eyre!("Failed to send hanshake message to remote node: {e}"))?;

    let mut client_proto = client_proto.next();

    let message = client_proto
        .read_message(&mut stream)
        .await
        .map_err(|e| eyre::eyre!("Failed to read init message from the remote node: {e}"))?;

    println!("Handshake completed!\n");
    println!("Successfully read and decrypted the init message from the remote node!\n");
    println!("Decrypted message (hex): {}", hex::encode(message));

    Ok(())
}
