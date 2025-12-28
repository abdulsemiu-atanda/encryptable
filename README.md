# encryptable

A Rust procedural macro for automatically deriving encryption and decryption capabilities on struct fields. This crate provides a convenient `Encryptable` derive macro that generates `Crypt` trait implementations to encrypt/decrypt specific fields in your structs.

## Features

- 🔐 **Selective Field Encryption**: Use attributes to specify which fields to encrypt or decrypt
- 🎯 **Type Support**: Works with `String`, `Option<String>`, and `Vec<String>` types
- 📝 **Digest Generation**: Automatic digest computation for fields using custom digest functions
- 🛠️ **Customizable Crypto**: Plug in your own encryption service with custom logic
- ⚡ **Zero-Cost Abstraction**: Generates code at compile-time with no runtime overhead

## Installation

Add this to your `Cargo.toml`:
```
toml
[dependencies]
encryptable = "0.1.0"
```
## Quick Start

### 1. Define Your Encryption Service

Implement an encryption service that provides `encrypt()` and `decrypt()` methods:
```rust
pub trait CryptKeeper {
  fn encrypt(&self, plaintext: &str) -> Result<String, std::io::Error>;
  fn decrypt(&self, ciphertext: &str) -> Result<String, std::io::Error>;
}

pub struct MyEncryptionService;

impl CryptKeeper for MyEncryptionService {
  fn encrypt(&self, plaintext: &str) -> Result<String, std::io::Error> {
  // Your encryption logic here
  Ok(plaintext.to_string()) // Example: no-op
  }

  fn decrypt(&self, ciphertext: &str) -> Result<String, std::io::Error> {
      // Your decryption logic here
      Ok(ciphertext.to_string()) // Example: no-op
  }
}
```
### 2. Define the `Crypt` Trait

Create a trait for your derived implementations:
```rust
pub trait Crypt {
  fn encrypt(&self) -> Self;
  fn decrypt(&self) -> Self;
}
```
### 3. Use the Derive Macro

Apply the `Encryptable` derive macro to your struct:
```rust
use encryptable::Encryptable;

#[derive(Encryptable)]
#[encryptable(service = "MyEncryptionService")]
struct User {
  #[encryptable(encrypt, decrypt)]
  email: String,
  #[encryptable(encrypt)]
  phone: String,
  name: String, // Not encrypted
}
```
## Usage Examples

### Basic Encryption and Decryption
```rust
let user = User {
  email: "user@example.com".to_string(),
  phone: "1234567890".to_string(),
  name: "John Doe".to_string(),
};

// Encrypt sensitive fields
let encrypted_user = user.encrypt();

// Decrypt fields
let decrypted_user = encrypted_user.decrypt();
```
### Optional Fields

```rust
#[derive(Encryptable)]
#[encryptable(service = "MyEncryptionService")]
struct Profile {
    #[encryptable(encrypt, decrypt)]
    bio: Option<String>,
}

let profile = Profile {
    bio: Some("Secret bio".to_string()),
};

let encrypted = profile.encrypt();
```


### Vector Fields

```rust
#[derive(Encryptable)]
#[encryptable(service = "MyEncryptionService")]
struct Document {
  #[encryptable(encrypt, decrypt)]
  tags: Vec<String>,
}

let doc = Document {
  tags: vec!["confidential".to_string()],
};

let encrypted = doc.encrypt();
```


### Digest Generation

Automatically generate digests of encrypted fields:

```rust
fn compute_digest(data: &str) -> String {
    // Your digest logic (e.g., HMAC-SHA256)
    format!("digest_{}", data)
}

#[derive(Encryptable)]
#[encryptable(service = "MyEncryptionService", digest = "compute_digest")]
struct SecureData {
    #[encryptable(encrypt)]
    sensitive: String,
    sensitive_digest: String, // Automatically populated
}
```


## Macro Attributes

### Container Attributes

- **`service`** (required): The encryption service instance that implements `encrypt()` and `decrypt()` methods
- **`digest`** (optional): A function reference for generating digests of encrypted fields (naming convention: `field_name` → `field_name_digest`)

### Field Attributes

- **`#[encryptable(encrypt)]`**: Encrypts this field during `encrypt()` call
- **`#[encryptable(decrypt)]`**: Decrypts this field during `decrypt()` call
- **`#[encryptable(encrypt, decrypt)]`**: Both encrypts and decrypts

## Supported Types

- `String`
- `Option<String>`
- `Vec<String>`

Fields with other types will be copied as-is without encryption.

## Requirements

- Rust 1.88 or later
- A custom encryption service implementing `encrypt()` and `decrypt()` methods that returns type `Result<String, Error>`
  - Error type can be any that suits your needs
- A `Crypt` trait definition in your crate

## How It Works

The `Encryptable` derive macro:

1. Parses container attributes to extract the encryption service and digest function
2. Inspects field attributes to determine which fields to encrypt/decrypt
3. Generates `Crypt` trait implementations with specialized handling for:
  - Plain strings
  - Optional fields (skips encryption if `None`)
  - Vector fields (encrypts each element)
  - Empty string optimization (skips encryption for empty values)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Author

Abdulsemiu Atanda - [semiu@live.com](mailto:semiu@live.com)
