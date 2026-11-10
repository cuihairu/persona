use super::*;

#[derive(Args, Debug)]
pub struct SshArgs {
    #[command(subcommand)]
    pub(crate) command: SshSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum SshSubcommand {
    /// Generate a new SSH key and store it in the vault
    Generate {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Key label (credential name)
        #[arg(short, long)]
        name: Option<String>,
        /// Key type (ed25519|rsa|ecdsa); rsa is 4096-bit, ecdsa is NIST P-256
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        /// Key comment (written into the key and the public key line)
        #[arg(short, long)]
        comment: Option<String>,
        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
    },
    /// List SSH keys for an identity
    List {
        /// Identity name
        #[arg(short, long)]
        identity: String,
    },
    /// Remove an SSH key by credential id
    Remove {
        /// Credential UUID to remove
        #[arg(long)]
        id: Uuid,
        /// Require confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Show agent running status
    Status,
    /// Start persona-ssh-agent and optionally print shell export commands
    AddToAgent {
        /// Identity name to filter: the agent loads only this identity's SSH keys
        #[arg(short, long)]
        identity: Option<String>,
        /// Print shell export command
        #[arg(long)]
        print_export: bool,
    },
    /// Show agent running status
    AgentStatus,
    /// Run a command while setting target host for agent policy
    Run {
        /// Target host (known_hosts policy + context-aware suggestion)
        #[arg(long)]
        host: String,
        /// Command to execute (use -- to separate)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Start persona-ssh-agent (alias of add-to-agent)
    StartAgent {
        /// Print shell export command
        #[arg(long)]
        print_export: bool,
    },
    /// List SSH keys across all identities
    ListAll,
    /// Import SSH key from seed (base64/hex)
    Import {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Key label
        #[arg(short, long)]
        name: Option<String>,
        /// ed25519 private seed in base64
        #[arg(long, conflicts_with = "seed_hex")]
        seed_base64: Option<String>,
        /// ed25519 private seed in hex
        #[arg(long, conflicts_with = "seed_base64")]
        seed_hex: Option<String>,
    },
    /// Import an OpenSSH private key file (id_ed25519 / id_rsa / id_ecdsa,
    /// passphrase-protected keys are unlocked at import; the stored copy is
    /// sealed by the vault's per-item key)
    ImportFile {
        /// Identity name to store the key under
        #[arg(short, long)]
        identity: String,
        /// Path to the OpenSSH private key file
        #[arg(short, long)]
        file: String,
        /// Key label (defaults to the file's comment, else the file name)
        #[arg(short, long)]
        name: Option<String>,
        /// Passphrase for encrypted keys (you will be prompted if omitted
        /// and the key needs one)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Print OpenSSH public key for a credential
    ExportPub {
        /// Credential UUID
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Stop persona-ssh-agent
    StopAgent,
    /// Sign a file with a vault SSH key (SSHSIG, `ssh-keygen -Y sign` wire
    /// format) — powers git commit signing via the `persona-ssh-sign` shim
    /// (see main.rs); can also be used directly
    GpgSign {
        /// Operation mode; only "sign" is supported
        #[arg(short = 'Y')]
        mode: String,
        /// Signature namespace (git uses "git"; binds the signature to one protocol)
        #[arg(short = 'n', default_value = "git")]
        namespace: String,
        /// Key spec: credential UUID, an "ssh-ed25519 <b64>" public key line,
        /// or a path to a file containing one. Defaults to the only vault key.
        #[arg(short = 'f')]
        key: Option<String>,
        /// File to sign
        file: String,
        /// Signature output path (defaults to <file>.sig, like ssh-keygen -Y sign)
        #[arg(short = 'o')]
        output: Option<String>,
    },
    /// Manage a vault public key in a host's authorized_keys. Runs the user's
    /// own `ssh` binary (same trust model as `ssh run`); the agent's host
    /// policy applies while the session is open
    Authorize {
        /// Identity owning the key
        #[arg(short, long)]
        identity: String,
        /// Target host (user@host allowed, passed to ssh)
        #[arg(long)]
        host: String,
        /// Credential UUID (optional when the identity holds exactly one SSH key)
        #[arg(long)]
        id: Option<Uuid>,
        /// Remove matching lines from authorized_keys instead of adding
        #[arg(long)]
        remove: bool,
        /// Print matching authorized_keys lines from the host
        #[arg(long, conflicts_with = "remove")]
        list: bool,
        /// Print the ssh invocation and remote script without running it
        #[arg(long)]
        dry_run: bool,
        /// Remote ssh port
        #[arg(long)]
        port: Option<u16>,
        /// Remote authorized_keys path (default: $HOME/.ssh/authorized_keys)
        #[arg(long)]
        remote_path: Option<String>,
    },
}
