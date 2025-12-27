extern crate proc_macro;

mod crypt;

use crypt::encryptable_derive_macro2;

#[proc_macro_derive(Encryptable, attributes(encryptable))]
pub fn encryptable_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
  encryptable_derive_macro2(input.into()).unwrap().into()
}
