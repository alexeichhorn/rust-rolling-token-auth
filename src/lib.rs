use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct Token {
    pub token: String,
    pub timestamp: i64,
}

impl Token {
    fn get_offset(&self, manager: &RollingTokenManager) -> i64 {
        self.timestamp - manager.current_timestamp()
    }
}

#[derive(Clone)]
pub struct RollingTokenManager {
    secret: Vec<u8>,
    interval: i64,
    tolerance: i64,
    active_tokens: Vec<Token>,
}

impl RollingTokenManager {
    pub fn new(secret: impl Into<Vec<u8>>, interval: i64, tolerance: Option<i64>) -> Self {
        Self {
            secret: secret.into(),
            interval,
            tolerance: tolerance.unwrap_or(1),
            active_tokens: Vec::new(),
        }
    }

    fn current_timestamp(&self) -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 / self.interval
    }

    pub fn generate_token_with_offset(&self, offset: i64) -> Token {
        let timestamp = self.current_timestamp() + offset;
        let encoded_timestamp = timestamp.to_string();

        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC can take key of any size");

        mac.update(encoded_timestamp.as_bytes());
        let result = mac.finalize();
        let token = hex::encode(result.into_bytes());

        Token { token, timestamp }
    }

    pub fn generate_token(&self) -> Token {
        self.generate_token_with_offset(0)
    }

    fn refresh_tokens(&mut self) {
        let current_time = self.current_timestamp();

        // Remove tokens outside tolerance
        self.active_tokens
            .retain(|token| (token.timestamp - current_time).abs() <= self.tolerance);

        if self.active_tokens.len() as i64 == 1 + 2 * self.tolerance {
            return;
        }

        // Create a set of timestamps we need to generate
        let mut needed_timestamps: Vec<i64> = (-self.tolerance..=self.tolerance).map(|offset| current_time + offset).collect();

        // Remove timestamps we already have
        for token in &self.active_tokens {
            needed_timestamps.retain(|&t| t != token.timestamp);
        }

        // Generate missing tokens
        for timestamp in needed_timestamps {
            let offset = timestamp - current_time;
            let token = self.generate_token_with_offset(offset);
            self.active_tokens.push(token);
        }
    }

    pub fn is_valid(&mut self, token: &str) -> bool {
        self.refresh_tokens();
        self.active_tokens.iter().any(|t| t.token == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_validation() {
        let mut manager = RollingTokenManager::new("test_secret", 30, Some(1));
        let token = manager.generate_token();
        assert!(manager.is_valid(&token.token));
        assert!(token.get_offset(&manager) == 0);

        let token_offset_1 = manager.generate_token_with_offset(1);
        assert!(manager.is_valid(&token_offset_1.token));
        assert!(token_offset_1.get_offset(&manager) == 1);

        let token_offset_2 = manager.generate_token_with_offset(2);
        assert!(!manager.is_valid(&token_offset_2.token)); // token is too far in the future -> invalid
        assert!(token_offset_2.get_offset(&manager) == 2);
    }

    #[test]
    fn test_invalid_token() {
        let mut manager = RollingTokenManager::new("test_secret", 30, Some(1));
        assert!(!manager.is_valid("invalid_token"));
    }
}
