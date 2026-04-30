use std::collections::HashSet;

// Adapted from https://github.com/serde-rs/serde/blob/1d7899d671c6f6155b63a39fa6001c9c48260821/serde_derive/src/bound.rs#L91

pub(crate) struct GenericsVisitor {
    // Set of all generic type parameters on the current struct.
    // Initialized up front.
    all_type_params: HashSet<syn::Ident>,

    // Field types that use one of the generic type parameters and therefore
    // require a bound on the full field type.
    bounded_types: HashSet<syn::Type>,
}

impl GenericsVisitor {
    pub(crate) fn new(existing_generics: &syn::Generics) -> Self {
        Self {
            all_type_params: existing_generics
                .type_params()
                .map(|param| param.ident.clone())
                .collect(),
            bounded_types: HashSet::default(),
        }
    }

    pub(crate) fn visit_field(&mut self, field: &syn::Field) {
        let field_ty = &field.ty;
        if self.type_needs_bound(field_ty) {
            self.bounded_types.insert(field_ty.clone());
        }
    }

    pub(crate) fn extend_where_clause(
        self,
        where_clause: &mut syn::WhereClause,
        bound: &syn::Path,
    ) {
        where_clause
            .predicates
            .extend(self.bounded_types.into_iter().map(|bounded_ty| {
                syn::WherePredicate::Type(syn::PredicateType {
                    lifetimes: None,
                    bounded_ty,
                    colon_token: Default::default(),
                    bounds: syn::punctuated::Punctuated::from_iter([syn::TypeParamBound::Trait(
                        syn::TraitBound {
                            paren_token: None,
                            modifier: syn::TraitBoundModifier::None,
                            lifetimes: None,
                            path: bound.clone(),
                        },
                    )]),
                })
            }));
    }

    fn type_needs_bound(&self, ty: &syn::Type) -> bool {
        use syn::Type::*;

        match ty {
            Array(ty) => self.type_needs_bound(&ty.elem),
            BareFn(ty) => {
                ty.inputs.iter().any(|arg| self.type_needs_bound(&arg.ty))
                    || self.return_type_needs_bound(&ty.output)
            }
            Group(ty) => self.type_needs_bound(&ty.elem),
            ImplTrait(ty) => ty
                .bounds
                .iter()
                .any(|bound| self.type_param_bound_needs_bound(bound)),
            Macro(ty) => self.macro_needs_bound(&ty.mac),
            Paren(ty) => self.type_needs_bound(&ty.elem),
            Path(ty) => {
                ty.qself
                    .as_ref()
                    .is_some_and(|qself| self.type_needs_bound(&qself.ty))
                    || self.path_needs_bound(&ty.path)
            }
            Ptr(ty) => self.type_needs_bound(&ty.elem),
            Reference(ty) => self.type_needs_bound(&ty.elem),
            Slice(ty) => self.type_needs_bound(&ty.elem),
            TraitObject(ty) => ty
                .bounds
                .iter()
                .any(|bound| self.type_param_bound_needs_bound(bound)),
            Tuple(ty) => ty.elems.iter().any(|elem| self.type_needs_bound(elem)),
            Infer(_) | Never(_) | Verbatim(_) | _ => false,
        }
    }

    fn path_needs_bound(&self, path: &syn::Path) -> bool {
        if path.leading_colon.is_none()
            && path
                .segments
                .first()
                .is_some_and(|segment| self.all_type_params.contains(&segment.ident))
        {
            return true;
        }

        path.segments
            .iter()
            .any(|segment| self.path_segment_needs_bound(segment))
    }

    fn path_segment_needs_bound(&self, segment: &syn::PathSegment) -> bool {
        self.path_arguments_need_bound(&segment.arguments)
    }

    fn path_arguments_need_bound(&self, arguments: &syn::PathArguments) -> bool {
        use syn::PathArguments::*;
        match arguments {
            None => false,
            AngleBracketed(arguments) => {
                use syn::GenericArgument::*;
                arguments.args.iter().any(|arg| match arg {
                    Type(arg) => self.type_needs_bound(arg),
                    AssocType(arg) => {
                        arg.generics.as_ref().is_some_and(|generics| {
                            self.angle_bracketed_arguments_need_bound(generics)
                        }) || self.type_needs_bound(&arg.ty)
                    }
                    Constraint(arg) => {
                        arg.generics.as_ref().is_some_and(|generics| {
                            self.angle_bracketed_arguments_need_bound(generics)
                        }) || arg
                            .bounds
                            .iter()
                            .any(|bound| self.type_param_bound_needs_bound(bound))
                    }
                    AssocConst(arg) => arg.generics.as_ref().is_some_and(|generics| {
                        self.angle_bracketed_arguments_need_bound(generics)
                    }),
                    Lifetime(_) | Const(_) | _ => false,
                })
            }
            Parenthesized(arguments) => {
                arguments
                    .inputs
                    .iter()
                    .any(|argument| self.type_needs_bound(argument))
                    || self.return_type_needs_bound(&arguments.output)
            }
        }
    }

    fn angle_bracketed_arguments_need_bound(
        &self,
        arguments: &syn::AngleBracketedGenericArguments,
    ) -> bool {
        use syn::GenericArgument::*;
        arguments.args.iter().any(|arg| match arg {
            Type(arg) => self.type_needs_bound(arg),
            AssocType(arg) => {
                arg.generics
                    .as_ref()
                    .is_some_and(|generics| self.angle_bracketed_arguments_need_bound(generics))
                    || self.type_needs_bound(&arg.ty)
            }
            Constraint(arg) => {
                arg.generics
                    .as_ref()
                    .is_some_and(|generics| self.angle_bracketed_arguments_need_bound(generics))
                    || arg
                        .bounds
                        .iter()
                        .any(|bound| self.type_param_bound_needs_bound(bound))
            }
            AssocConst(arg) => arg
                .generics
                .as_ref()
                .is_some_and(|generics| self.angle_bracketed_arguments_need_bound(generics)),
            Lifetime(_) | Const(_) | _ => false,
        })
    }

    fn return_type_needs_bound(&self, return_type: &syn::ReturnType) -> bool {
        use syn::ReturnType::*;
        match return_type {
            Default => false,
            Type(_, output) => self.type_needs_bound(output),
        }
    }

    fn type_param_bound_needs_bound(&self, bound: &syn::TypeParamBound) -> bool {
        if let syn::TypeParamBound::Trait(bound) = bound {
            self.path_needs_bound(&bound.path)
        } else {
            false
        }
    }

    // Type parameter should not be considered used by a macro path.
    //
    //     struct TypeMacro<T> {
    //         mac: T!(),
    //         marker: PhantomData<T>,
    //     }
    #[expect(clippy::unused_self)]
    const fn macro_needs_bound(&self, _mac: &syn::Macro) -> bool {
        false
    }
}
