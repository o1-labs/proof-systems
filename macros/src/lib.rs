extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_derive(GateImpl)]
pub fn gate_impl_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    gate_impl_macro(&ast)
}

fn gate_impl_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl<F: PrimeField> #name<F> {
            pub fn typ() -> String {
                String::from(stringify!(#name))
                // std::any::type_name::<Self>().to_string()
            }

            pub fn create<S: ExprOps<F>>() -> Box<dyn Gate<F, S>> {
                Box::new(Self::default())
            }
        }
    };
    gen.into()
}
