use proc_macro2::{TokenStream, Span};
use quote::quote;
use syn::{DeriveInput, Expr, Field, Type, Ident};

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(encryptable))]
struct EncryptableAttributes {
  /// Rust struct that has encrypt and decrypt methods implemented
  service: Expr,
  /// Function that generates a digest of the supplied [str] value
  digest: Option<Expr>,
}

#[derive(deluxe::ExtractAttributes, Default)]
#[deluxe(attributes(encryptable))]
struct EncryptableFieldAttributes {
  #[deluxe(default)]
  encrypt: bool,
  #[deluxe(default)]
  decrypt: bool,
}

type EncryptableFieldAttributesDictionary = std::collections::HashMap<Field, EncryptableFieldAttributes>;

fn extract_encryptable_field_attributes(ast: &mut DeriveInput) -> deluxe::Result<EncryptableFieldAttributesDictionary> {
  let mut field_attributes = EncryptableFieldAttributesDictionary::new();

  if let syn::Data::Struct(structure) = &mut ast.data {
    for field in structure.fields.iter_mut() {
      let attributes: EncryptableFieldAttributes = deluxe::extract_attributes(field)?;

      field_attributes.insert(field.to_owned(), attributes);
    }
  }

  Ok(field_attributes)
}

fn is_option(ty: &Type) -> bool {
  let mut result = false;

  if let Type::Path(type_path) = ty {
    result = type_path.path.segments.iter().next().unwrap().ident == "Option";
  }

  result
}

fn is_vector(ty: &Type) -> bool {
  let mut result = false;

  if let Type::Path(type_path) = ty {
    result = type_path.path.segments.iter().next().unwrap().ident == "Vec";
  }

  result
}

fn encrypt_field(field: &Field, service: &Expr) -> TokenStream {
  let ident = field.ident.as_ref().unwrap();

  if is_option(&field.ty) {
    quote! {
      #ident: if let Some(value) = &self.#ident {
        if value.is_empty() {
          Some(value.to_owned())
        } else {
          Some(#service.encrypt(value).unwrap())
        }
      } else {
        None
      }
    }
  } else if is_vector(&field.ty) {
    quote! {
      #ident: if self.#ident.is_empty() {
        self.#ident.to_owned()
      } else {
        self.#ident.iter().map(|value| #service.encrypt(value).unwrap()).collect()
      }
    }
  } else {
    quote! {
      #ident: if self.#ident.is_empty() { self.#ident.to_owned() } else { #service.encrypt(&self.#ident).unwrap() }
    }
  }
}

fn decrypt_field(field: &Field, service: &Expr) -> TokenStream {
  let ident = field.ident.as_ref().unwrap();

  if is_option(&field.ty) {
    quote! {
      #ident: if let Some(value) = &self.#ident {
        if value.is_empty() {
          Some(value.to_owned())
        } else {
          Some(#service.decrypt(value).unwrap())
        }
      } else {
        None
      }
    }
  } else if is_vector(&field.ty) {
    quote! {
      #ident: if self.#ident.is_empty() {
        self.#ident.to_owned()
      } else {
        self.#ident.iter().map(|value| #service.decrypt(value).unwrap()).collect()
      }
    }
  } else {
    quote! {
      #ident: if self.#ident.is_empty() { self.#ident.to_owned() } else { #service.decrypt(&self.#ident).unwrap() }
    }
  }
}

pub fn encryptable_derive_macro2(item: proc_macro2::TokenStream) -> deluxe::Result<proc_macro2::TokenStream> {
  let mut ast: DeriveInput = syn::parse2(item)?;

  let EncryptableAttributes { service, digest } = deluxe::extract_attributes(&mut ast)?;
  let field_attributes = extract_encryptable_field_attributes(&mut ast)?;

  // Generate syntax tree
  let encrypt_fields = field_attributes.iter().map(|(field, attributes)| {
    let ident = field.ident.as_ref().unwrap();
    let field_name = ident.to_string();

    if attributes.encrypt {
      encrypt_field(field, &service)
    } else if field_name.ends_with("digest") && digest.is_some() {
      let func = digest.as_ref().unwrap();
      let parent = Ident::new(&field_name.replace("_digest", ""), Span::call_site());

      quote! { #ident: if self.#parent.is_empty() { self.#ident.to_owned() } else { #func(&self.#parent) } }
    } else {
      quote! {
        #ident: self.#ident.to_owned()
      }
    }
  });
  let decrypt_fields = field_attributes.iter().map(|(field, attributes)| {
    let ident = field.ident.as_ref().unwrap();

    if attributes.decrypt {
      decrypt_field(field, &service)
    } else {
      quote! {
        #ident: self.#ident.to_owned()
      }
    }
  });

  // define impl variables
  let ident = &ast.ident;
  let (impl_generics, type_generics, where_clause) = ast.generics.split_for_impl();

  Ok(quote! {
    impl #impl_generics Crypt for #ident #type_generics #where_clause {
      fn encrypt(&self) -> Self {
       Self {
        #(#encrypt_fields),*
       }
      }

      fn decrypt(&self) -> Self {
       Self {
        #(#decrypt_fields),*
       }
      }
    }
  })
}
