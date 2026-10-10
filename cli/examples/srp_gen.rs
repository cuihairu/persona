//! Throwaway helper: print base64 salt/verifier for an SRP registration.
//! Usage: cargo run -p persona-cli --example srp_gen -- <device> <password>

use persona_core::auth::srp::register_verifier;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let device = args.get(1).expect("device name").clone();
    let password = args.get(2).expect("password").clone();
    let reg = register_verifier(&device, &password).expect("register_verifier");
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
    println!("SALT={}", b64.encode(&reg.salt));
    println!("VERIFIER={}", b64.encode(&reg.verifier));
}
