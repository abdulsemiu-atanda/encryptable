use hex::ToHex;
use hmac::{Hmac, Mac};
use sha2::{Sha256, digest::InvalidLength};

type HmacSha256 = Hmac<Sha256>;

pub fn data_digest(key: &str, data: &str) -> Result<String, InvalidLength> {
  let mut hash = HmacSha256::new_from_slice(key.as_bytes())?;

  hash.update(data.as_bytes());

  Ok(hash.finalize().into_bytes().encode_hex())
}

trait CryptKeeper {
  fn encrypt(&self, plaintext: &str) -> Result<String, std::io::Error>;
  fn decrypt(&self, ciphertext: &str) -> Result<String, std::io::Error>;
}

pub struct SymmetricEncryption;

impl CryptKeeper for SymmetricEncryption {
  fn decrypt(&self, ciphertext: &str) -> Result<String, std::io::Error> {
    Ok(String::from_utf8(hex::decode(ciphertext).expect("Invalid hex literal")).expect("Failed to convert to string"))
  }

  fn encrypt(&self, plaintext: &str) -> Result<String, std::io::Error> {
    Ok(plaintext.encode_hex())
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use encryptable::Encryptable;

   trait Crypt {
    fn encrypt(&self) -> Self;
    fn decrypt(&self) -> Self;
  }

  fn digest(data: &str) -> String {
    data_digest("test_key", data).expect("Failed to digest data")
  }

  #[test]
  fn test_encryptable_derive() {
    #[derive(Debug, Encryptable)]
    #[encryptable(service = SymmetricEncryption, digest = digest)]
    struct TestData {
      #[encryptable(encrypt, decrypt)]
      name: String,
      name_digest: String
    }

    let payload = TestData { name: "Jake".into(), name_digest: "".into() };
    let encrypted = payload.encrypt();

    assert_ne!(encrypted.name, payload.name);
    assert_ne!(encrypted.name_digest, payload.name_digest);

    let decrypted = encrypted.decrypt();

    assert_eq!(decrypted.name, payload.name)
  }

  #[test]
  fn test_encryptable_derive_empty_string() {
    #[derive(Debug, Encryptable)]
    #[encryptable(service = SymmetricEncryption, digest = digest)]
    struct TestData {
      #[encryptable(encrypt, decrypt)]
      name: String,
      name_digest: String
    }

    let payload = TestData { name: "".into(), name_digest: "".into() };
    let encrypted = payload.encrypt();

    assert_eq!(encrypted.name, payload.name);
    assert_eq!(encrypted.name_digest, payload.name_digest);

    let decrypted = encrypted.decrypt();

    assert_eq!(decrypted.name, payload.name)
  }

  #[test]
  fn test_encryptable_derive_vector() {
    #[derive(Debug, Encryptable)]
    #[encryptable(service = SymmetricEncryption, digest = digest)]
    struct TestData {
      #[encryptable(encrypt, decrypt)]
      sessions: Vec<String>,
    }

    let payload = TestData { sessions: vec!["dances".into(), "shopping".into()] };
    let encrypted = payload.encrypt();

    assert_eq!(encrypted.sessions.len(), payload.sessions.len());
    assert_ne!(encrypted.sessions[0], payload.sessions[0]);

    let decrypted = encrypted.decrypt();

    assert_eq!(decrypted.sessions.len(), payload.sessions.len());
    assert_eq!(decrypted.sessions[0], payload.sessions[0]);
  }

  #[test]
  fn test_encryptable_derive_optional() {
    #[derive(Debug, Encryptable)]
    #[encryptable(service = SymmetricEncryption, digest = digest)]
    struct TestData {
      #[encryptable(encrypt, decrypt)]
      name: Option<String>,
    }

    let payload = TestData { name: Some("dances".into()) };
    let encrypted = payload.encrypt();

    assert!(encrypted.name.is_some());
    assert_ne!(encrypted.name.as_ref().unwrap(), payload.name.as_ref().unwrap());

    let decrypted = encrypted.decrypt();

    assert!(decrypted.name.is_some());
    assert_eq!(decrypted.name.as_ref().unwrap(), payload.name.as_ref().unwrap());
  }
}
