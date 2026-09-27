use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use tokio::net::UnixStream;

use crate::protocol::frame::{read_json_frame, write_json_frame};
use crate::protocol::message::{ControlRequest, ControlResponse, Message};
use crate::{Error, Result};

pub async fn request(
    socket: &Path,
    request: ControlRequest,
    timeout: Duration,
) -> Result<ControlResponse> {
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(socket).await?;
        write_json_frame(&mut stream, &request).await?;
        read_json_frame(&mut stream).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}

pub fn print_response(response: ControlResponse, json: bool) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(match response {
            ControlResponse::Ok { .. } => 0,
            ControlResponse::Error { .. } => 1,
        });
    }

    match response {
        ControlResponse::Ok {
            peers: Some(peers), ..
        } => {
            if peers.is_empty() {
                println!("no peers connected");
            } else {
                println!("CREDENTIAL\tNAME\tREMOTE\tCONNECTED");
                for peer in peers {
                    println!(
                        "{}\t{}\t{}\t{}s",
                        peer.credential, peer.name, peer.remote_addr, peer.connected_secs
                    );
                }
            }
            Ok(0)
        }
        ControlResponse::Ok {
            result: Some(result),
            ..
        } => match *result {
            Message::ExecResponse {
                exit_code,
                stdout_b64,
                stderr_b64,
                truncated,
                timed_out,
                error,
                ..
            } => {
                let stdout = STANDARD
                    .decode(stdout_b64)
                    .map_err(|_| Error::Control("invalid stdout encoding from daemon".into()))?;
                let stderr = STANDARD
                    .decode(stderr_b64)
                    .map_err(|_| Error::Control("invalid stderr encoding from daemon".into()))?;
                std::io::stdout().write_all(&stdout)?;
                std::io::stderr().write_all(&stderr)?;
                if truncated {
                    eprintln!("tetherd: output truncated");
                }
                if timed_out {
                    eprintln!("tetherd: command timed out");
                }
                if let Some(error) = error {
                    eprintln!("tetherd: {error}");
                    return Ok(1);
                }
                Ok(exit_code.unwrap_or(1).clamp(0, 255))
            }
            _ => Err(Error::Control("unexpected control response message".into())),
        },
        ControlResponse::Ok { .. } => Ok(0),
        ControlResponse::Error { message } => {
            eprintln!("tetherd: {message}");
            Ok(1)
        }
    }
}
