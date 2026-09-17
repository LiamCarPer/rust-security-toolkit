use std::io::Read;

use rts_replay::{ReplayRequest, run_request};

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read request from stdin: {}", e);
        std::process::exit(2);
    }
    let request: ReplayRequest = match serde_json::from_str(&input) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("invalid replay request JSON: {}", e);
            std::process::exit(2);
        }
    };
    if request.protocol_version != rts_replay::PROTOCOL_VERSION {
        eprintln!(
            "protocol version mismatch: request {} vs supported {}",
            request.protocol_version,
            rts_replay::PROTOCOL_VERSION
        );
        std::process::exit(2);
    }
    match run_request(&request) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("failed to serialize replay report: {}", e);
                std::process::exit(3);
            }
        },
        Err(e) => {
            eprintln!("replay failed: {:#}", e);
            std::process::exit(1);
        }
    }
}
