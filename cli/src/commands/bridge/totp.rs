use super::*;

pub(super) fn generate_totp_code_from_data(data: &TwoFactorData) -> Result<(String, u32, u32)> {
    let secret_bytes = decode_totp_secret(&data.secret_key)?;
    let now = chrono::Utc::now();
    let period = data.period.max(1) as u64;
    let timestamp = now.timestamp().max(0) as u64;
    let counter = timestamp / period;
    let digits = data.digits.clamp(4, 10) as u32;
    let code_num = hotp(&secret_bytes, counter, &data.algorithm)?;
    // 10^10 exceeds u32::MAX, so the power and modulus are computed in u64.
    let modulo = 10_u64.pow(digits);
    let value = u64::from(code_num) % modulo;
    let code = format!("{:0width$}", value, width = digits as usize);
    let remaining = (period - (timestamp % period)) as u32;
    Ok((code, remaining, data.period.max(1)))
}

pub(super) fn hotp(secret: &[u8], counter: u64, algorithm: &str) -> Result<u32> {
    let msg = counter.to_be_bytes();
    let algo = algorithm.to_ascii_uppercase();
    let hash = if algo == "SHA256" {
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else if algo == "SHA512" {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        type HmacSha1 = Hmac<sha1::Sha1>;
        let mut mac = HmacSha1::new_from_slice(secret).context("invalid secret")?;
        mac.update(&msg);
        mac.finalize().into_bytes().to_vec()
    };

    let offset = (hash.last().copied().unwrap_or(0) & 0x0f) as usize;
    if offset + 4 > hash.len() {
        return Err(anyhow!("invalid_hmac_output"));
    }
    let slice = &hash[offset..offset + 4];
    let binary = ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32;
    Ok(binary)
}

pub(super) fn decode_totp_secret(secret: &str) -> Result<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>()
        .trim_matches('=')
        .to_string();
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|e| anyhow!("invalid_base32_secret: {e}"))
}
