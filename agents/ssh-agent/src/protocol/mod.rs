use super::*;

/// SSH agent wire-protocol maximum frame size (u32 length prefix is attacker-
/// controlled from the socket; a 4-byte header must not drive an unbounded
/// allocation. Mirrors the bounds-checking convention of `read_ssh_string`).
const MAX_AGENT_PKT_LEN: usize = 16 * 1024 * 1024;

pub async fn handle_connection(agent: &mut Agent, mut stream: AgentStream) -> Result<()> {
    use byteorder::{BigEndian, ByteOrder};
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let pkt_len = BigEndian::read_u32(&len_buf) as usize;
        if pkt_len > MAX_AGENT_PKT_LEN {
            // Malformed/oversized frame from a peer: drop the connection rather
            // than attempting a huge allocation from a 4-byte length prefix.
            warn!(
                pkt_len,
                "agent frame exceeds MAX_AGENT_PKT_LEN, dropping connection"
            );
            break;
        }
        let mut pkt = vec![0u8; pkt_len];
        stream.read_exact(&mut pkt).await?;
        if pkt.is_empty() {
            continue;
        }
        let msg_type = pkt[0];
        match msg_type {
            11 => {
                // SSH_AGENTC_REQUEST_IDENTITIES
                let resp = agent.identities_answer()?;
                stream.write_all(&resp).await?;
            }
            13 => {
                // SSH_AGENTC_SIGN_REQUEST
                let resp = agent.sign_response(&pkt[1..]).await?;
                stream.write_all(&resp).await?;
            }
            other => {
                warn!("Unsupported message type: {}", other);
                // send failure (5)
                let mut out = vec![0u8; 5];
                BigEndian::write_u32(&mut out[0..4], 1);
                out[4] = 5u8;
                stream.write_all(&out).await?;
            }
        }
    }
    Ok(())
}

pub(super) fn wrap_packet(payload: Vec<u8>) -> Vec<u8> {
    use byteorder::{BigEndian, ByteOrder};
    let len = payload.len() as u32;
    let mut out = vec![0u8; 4];
    BigEndian::write_u32(&mut out[0..4], len);
    out.extend_from_slice(&payload);
    out
}

pub(super) fn write_ssh_string(buf: &mut Vec<u8>, s: &[u8]) -> Result<()> {
    use byteorder::{BigEndian, WriteBytesExt};
    buf.write_u32::<BigEndian>(s.len() as u32)?;
    buf.extend_from_slice(s);
    Ok(())
}

pub(super) fn read_ssh_string(buf: &mut &[u8]) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, ReadBytesExt};
    let len = buf.read_u32::<BigEndian>()? as usize;
    if buf.len() < len {
        anyhow::bail!("ssh string length out of bounds");
    }
    let (s, rest) = buf.split_at(len);
    *buf = rest;
    Ok(s.to_vec())
}

pub(super) fn failure_packet() -> Vec<u8> {
    use byteorder::{BigEndian, ByteOrder};
    let mut out = vec![0u8; 5];
    BigEndian::write_u32(&mut out[0..4], 1);
    out[4] = 5u8;
    out
}
