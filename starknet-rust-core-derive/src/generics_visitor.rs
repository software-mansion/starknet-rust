use std::collections::HashSet;

use syn::{punctuated::Pair, Generics, Path, Token, Type, WhereClause};

// Adapted from https://github.com/serde-rs/serde/blob/1d7899d671c6f6155b63a39fa6001c9c48260821/serde_derive/src/bound.rs#L91

pub struct GenericsVisitor<'ast> {
    existing_generics: Generics,

    // Set of all generic type parameters on the current struct.
    // Initialized up front.
    all_type_params: HashSet<syn::Ident>,

    // Set of generic type parameters used in fields.
    // Filled in as the visitor sees them.
    relevant_type_params: HashSet<syn::Ident>,

    // Fields whose type is an associated type of one of the generic type
    // parameters.
    associated_type_usage: Vec<&'ast syn::TypePath>,
}

impl<'ast> GenericsVisitor<'ast> {
    pub fn new(existing_generics: &Generics) -> Self {
        Self {
            existing_generics: existing_generics.clone(),
            all_type_params: existing_generics
                .type_params()
                .map(|param| param.ident.clone())
                .collect(),
            relevant_type_params: HashSet::default(),
            associated_type_usage: Vec::default(),
        }
    }

    pub fn extend_where_clause(self, where_clause: &mut WhereClause, bound: &Path) {
        where_clause.predicates.extend(
            self.existing_generics
                .type_params()
                .filter_map(|param| {
                    self.relevant_type_params
                        .contains(&param.ident)
                        .then(|| syn::TypePath {
                            qself: None,
                            path: param.ident.clone().into(),
                        })
                })
                .chain(self.associated_type_usage.into_iter().cloned())
                .map(|bounded_ty| {
                    syn::WherePredicate::Type(syn::PredicateType {
                        lifetimes: None,
                        bounded_ty: syn::Type::Path(bounded_ty),
                        colon_token: <Token![:]>::default(),
                        bounds: vec![syn::TypeParamBound::Trait(syn::TraitBound {
                            paren_token: None,
                            modifier: syn::TraitBoundModifier::None,
                            lifetimes: None,
                            path: bound.clone(),
                        })]
                        .into_iter()
                        .collect(),
                    })
                }),
        );
    }

    pub fn visit_field(&mut self, field: &'ast syn::Field) {
        if let syn::Type::Path(ty) = ungroup(&field.ty) {
            if let Some(Pair::Punctuated(t, _)) = ty.path.segments.pairs().next() {
                if self.all_type_params.contains(&t.ident) {
                    self.associated_type_usage.push(ty);
                }
            }
        }
        self.visit_type(&field.ty);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path.leading_colon.is_none() && path.segments.len() == 1 {
            let id = &path.segments[0].ident;
            if self.all_type_params.contains(id) {
                self.relevant_type_params.insert(id.clone());
            }
        }
        for segment in &path.segments {
            self.visit_path_segment(segment);
        }
    }

    // Everything below is simply traversing the syntax tree.

    fn visit_type(&mut self, ty: &'ast syn::Type) {
        match ty {
            syn::Type::Array(ty) => self.visit_type(&ty.elem),
            syn::Type::BareFn(ty) => {
                for arg in &ty.inputs {
                    self.visit_type(&arg.ty);
                }
                self.visit_return_type(&ty.output);
            }
            syn::Type::Group(ty) => self.visit_type(&ty.elem),
            syn::Type::ImplTrait(ty) => {
                for bound in &ty.bounds {
                    self.visit_type_param_bound(bound);
                }
            }
            syn::Type::Macro(ty) => self.visit_macro(&ty.mac),
            syn::Type::Paren(ty) => self.visit_type(&ty.elem),
            syn::Type::Path(ty) => {
                if let Some(qself) = &ty.qself {
                    self.visit_type(&qself.ty);
                }
                self.visit_path(&ty.path);
            }
            syn::Type::Ptr(ty) => self.visit_type(&ty.elem),
            syn::Type::Reference(ty) => self.visit_type(&ty.elem),
            syn::Type::Slice(ty) => self.visit_type(&ty.elem),
            syn::Type::TraitObject(ty) => {
                for bound in &ty.bounds {
                    self.visit_type_param_bound(bound);
                }
            }
            syn::Type::Tuple(ty) => {
                for elem in &ty.elems {
                    self.visit_type(elem);
                }
            }

            syn::Type::Infer(_) | syn::Type::Never(_) | syn::Type::Verbatim(_) => {}

            _ => {}
        }
    }

    fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
        self.visit_path_arguments(&segment.arguments);
    }

    fn visit_path_arguments(&mut self, arguments: &'ast syn::PathArguments) {
        match arguments {
            syn::PathArguments::None => {}
            syn::PathArguments::AngleBracketed(arguments) => {
                for arg in &arguments.args {
                    match arg {
                        syn::GenericArgument::Type(arg) => self.visit_type(arg),
                        syn::GenericArgument::AssocType(arg) => self.visit_type(&arg.ty),
                        syn::GenericArgument::Lifetime(_)
                        | syn::GenericArgument::Const(_)
                        | syn::GenericArgument::AssocConst(_)
                        | syn::GenericArgument::Constraint(_) => {}
                        _ => {}
                    }
                }
            }
            syn::PathArguments::Parenthesized(arguments) => {
                for argument in &arguments.inputs {
                    self.visit_type(argument);
                }
                self.visit_return_type(&arguments.output);
            }
        }
    }

    fn visit_return_type(&mut self, return_type: &'ast syn::ReturnType) {
        match return_type {
            syn::ReturnType::Default => {}
            syn::ReturnType::Type(_, output) => self.visit_type(output),
        }
    }

    fn visit_type_param_bound(&mut self, bound: &'ast syn::TypeParamBound) {
        match bound {
            syn::TypeParamBound::Trait(bound) => self.visit_path(&bound.path),
            syn::TypeParamBound::Lifetime(_)
            | syn::TypeParamBound::PreciseCapture(_)
            | syn::TypeParamBound::Verbatim(_) => {}
            _ => {}
        }
    }

    // Type parameter should not be considered used by a macro path.
    //
    //     struct TypeMacro<T> {
    //         mac: T!(),
    //         marker: PhantomData<T>,
    //     }
    fn visit_macro(&mut self, _mac: &'ast syn::Macro) {}
}

fn ungroup(mut ty: &Type) -> &Type {
    while let Type::Group(group) = ty {
        ty = &group.elem;
    }
    ty
}
