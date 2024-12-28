# Rolling Token Authentication

A simple and secure rolling token authentication system for Rust applications. It generates and validates time-based tokens using HMAC-SHA256.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rolling-token-auth = "0.1.0"
```

## Usage

### Initialization
```rust
use rolling_token_auth::RollingTokenManager;

let mut manager = RollingTokenManager::new("secret", 3600, None);
```

The parameters are:
- `secret`: The secret key used for token generation (can be a string or bytes)
- `interval`: Defines how long a token is valid in seconds. Shorter intervals are more secure
- `tolerance`: Optional parameter defining how many intervals to accept before/after the current one (defaults to 1)

Both `secret` and `interval` must match between generation and verification.

### Token Generation
```rust
// Generate a token for the current timestamp
let token = manager.generate_token();

// Or generate a token with a specific offset
let future_token = manager.generate_token_with_offset(1);
```

### Token Verification
```rust
if manager.is_valid(&token.token) {
    println!("Token is valid!");
}
```

The `tolerance` parameter (set during initialization) defines how many tokens from the past and future are still valid. With the default tolerance of 1:
- The previous interval's token is valid
- The current interval's token is valid
- The next interval's token is valid

## Example

```rust
use rolling_token_auth::RollingTokenManager;

// Create a manager with 1-hour intervals
let mut manager = RollingTokenManager::new("my_secret", 3600, Some(1));

// Generate a token
let token = manager.generate_token();

// Validate the token
assert!(manager.is_valid(&token.token));
```
