use super::*;

#[derive(Default)]
pub(crate) struct TotpTemplate {
    pub(crate) secret: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) account: Option<String>,
    pub(crate) algorithm: Option<String>,
    pub(crate) digits: Option<u8>,
    pub(crate) period: Option<u32>,
    /// 计数器型 HOTP（RFC 4226）；otpauth://hotp/ 的 URI/QR 与 --hotp 设置
    pub(crate) hotp: Option<bool>,
    /// HOTP 起始计数器（URI 的 counter 参数或 --counter）
    pub(crate) counter: Option<u64>,
}

impl TotpTemplate {
    pub(crate) fn merge(&mut self, other: TotpTemplate) {
        if self.secret.is_none() {
            self.secret = other.secret;
        }
        if self.issuer.is_none() {
            self.issuer = other.issuer;
        }
        if self.account.is_none() {
            self.account = other.account;
        }
        if self.algorithm.is_none() {
            self.algorithm = other.algorithm;
        }
        if self.digits.is_none() {
            self.digits = other.digits;
        }
        if self.period.is_none() {
            self.period = other.period;
        }
        if self.hotp.is_none() {
            self.hotp = other.hotp;
        }
        if self.counter.is_none() {
            self.counter = other.counter;
        }
    }

    pub(crate) fn finalize(self) -> Result<FinalTotpConfig> {
        let secret = self
            .secret
            .ok_or_else(|| anyhow!("Secret not provided via QR/otpauth/--secret"))?;
        let issuer = self.issuer.unwrap_or_default();
        let account = self.account.unwrap_or_else(|| "TOTP".into());
        let algorithm = self.algorithm.unwrap_or_else(|| "SHA1".into());
        let digits = self.digits.unwrap_or(6);
        let period = self.period.unwrap_or(30);
        Ok(FinalTotpConfig {
            secret,
            issuer,
            account,
            algorithm: algorithm.to_uppercase(),
            digits,
            period,
            hotp: self.hotp.unwrap_or(false),
            counter: self.counter,
        })
    }
}

pub(crate) struct FinalTotpConfig {
    pub(crate) secret: String,
    pub(crate) issuer: String,
    pub(crate) account: String,
    pub(crate) algorithm: String,
    pub(crate) digits: u8,
    pub(crate) period: u32,
    pub(crate) hotp: bool,
    pub(crate) counter: Option<u64>,
}
