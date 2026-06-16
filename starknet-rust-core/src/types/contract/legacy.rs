use alloc::{borrow::ToOwned, boxed::Box, collections::BTreeMap, format, string::String, vec::Vec};

use crate::{
    crypto::compute_hash_on_elements,
    serde::{num_hex::u64 as u64_hex, unsigned_field_element::UfeHex},
    types::{
        Felt, FunctionStateMutability, LegacyContractAbiEntry, LegacyContractEntryPoint,
        LegacyEntryPointsByType, LegacyEventAbiEntry, LegacyEventAbiType, LegacyFunctionAbiEntry,
        LegacyFunctionAbiType, LegacyStructAbiEntry, LegacyStructAbiType, LegacyStructMember,
        LegacyTypedParameter,
        contract::{ComputeClassHashError, JsonError},
    },
    utils::{cairo_short_string_to_felt, starknet_keccak},
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError, ser::SerializeSeq,
};
use serde_json_pythonic::to_string_pythonic;
use serde_with::{SerializeAs, serde_as};

#[cfg(feature = "std")]
use crate::types::{CompressedLegacyContractClass, contract::CompressProgramError};
#[cfg(feature = "std")]
use flate2::{Compression, write::GzEncoder};

const API_VERSION: Felt = Felt::ZERO;

/// A legacy (Cairo 0) contract class in a representation identical to the compiler output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyContractClass {
    // Some pre-0.10 artifacts serialize `abi` as `null` rather than `[]`, and the distinction is
    // load-bearing for the hinted class hash. The field is therefore `Option`, and always
    // serialized (never skipped) to preserve the original shape.
    /// Contract ABI.
    pub abi: Option<Vec<RawLegacyAbiEntry>>,
    /// Contract entrypoints.
    pub entry_points_by_type: RawLegacyEntryPoints,
    /// The Cairo program of the contract containing the actual bytecode.
    pub program: LegacyProgram,
}

/// Legacy (Cairo 0) contract entrypoints by types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct RawLegacyEntryPoints {
    /// Entrypoints of type `CONSTRUCTOR` used during contract deployment.
    pub constructor: Vec<RawLegacyEntryPoint>,
    /// Entrypoints of type `EXTERNAL` used for invocations from outside contracts.
    pub external: Vec<RawLegacyEntryPoint>,
    /// Entrypoints of type `L1_HANDLER` used for handling L1-to-L2 messages.
    pub l1_handler: Vec<RawLegacyEntryPoint>,
}

/// Legacy (Cairo 0) program containing bytecode and other data necessary for execution.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyProgram {
    /// Attributes that provide additional context for certain sections of the bytecode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<LegacyAttribute>>,
    /// The list of Cairo builtins this program has access to.
    pub builtins: Vec<String>,
    // This field was introduced in Cairo 0.10.0. By making it optional we're keeping compatibility
    // with older artifacts. This decision should be reviewd in the future.
    /// Version of the compiler used to compile this contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    /// The Cairo assembly bytecode of the contract.
    #[serde_as(as = "Vec<UfeHex>")]
    pub data: Vec<Felt>,
    /// Debug information which is optionally emitted by the compiler. This field is not used for
    /// class declaration or class hash calculation.
    pub debug_info: Option<LegacyDebugInfo>,
    /// Legacy hints for non-determinism.
    pub hints: BTreeMap<u64, Vec<LegacyHint>>,
    /// A map of identifiers by name.
    pub identifiers: BTreeMap<String, LegacyIdentifier>,
    /// The main scope/namespace where all identifiers this program defines live in, usually
    /// `__main__`.
    pub main_scope: String,
    // Impossible to use [Felt] here as by definition field elements are smaller
    // than prime
    /// The STARK field prime.
    pub prime: String,
    /// Data for tracking
    /// [references](https://docs.cairo-lang.org/how_cairo_works/consts.html#references).
    pub reference_manager: LegacyReferenceManager,
}

/// An legacy (Cairo 0) contract entrypoint for translating a selector to a bytecode offset.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct RawLegacyEntryPoint {
    /// Offset in the bytecode.
    pub offset: LegacyEntrypointOffset,
    /// Selector of the entrypoint, usually computed as the Starknet Keccak of the function name.
    #[serde_as(as = "UfeHex")]
    pub selector: Felt,
}

/// Legacy (Cairo 0) program attribute that provide additional context for certain sections of the
/// bytecode.
///
/// Attributes are usually used for providing error messages when an assertion fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyAttribute {
    /// The scopes from which the attribute is accessible.
    #[serde(default)]
    pub accessible_scopes: Vec<String>,
    /// The ending PC of the segment that has access to the attribute.
    pub end_pc: u64,
    /// Data needed for tracking the allocation pointer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_tracking_data: Option<LegacyFlowTrackingData>,
    /// Name of the attribute.
    pub name: String,
    /// The starting PC of the segment that has access to the attribute.
    pub start_pc: u64,
    /// Value of the attribute.
    pub value: String,
}

/// Debug information generated by the legacy (Cairo 0) compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyDebugInfo {
    /// A partial map from file name to its content. Files that are not in the map, are assumed to
    /// exist in the file system.
    pub file_contents: BTreeMap<String, String>,
    /// A map from (relative) PC to the location of the instruction.
    pub instruction_locations: BTreeMap<u64, LegacyInstructionLocation>,
}

/// Legacy (Cairo 0) hints for introducing non-determinism into a Cairo program.
///
/// These hints are implemented in Python that execute arbitrary code to fill Cairo VM memory. In
/// a public network like Starknet, a predefined list of hints are whitelisted to prevent deployment
/// of malicious code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyHint {
    /// The scopes from which the hint is accessible.
    pub accessible_scopes: Vec<String>,
    /// The Python code of the hint.
    pub code: String,
    /// Data needed for tracking the allocation pointer.
    pub flow_tracking_data: LegacyFlowTrackingData,
}

/// Legacy (Cairo 0) program identifiers.
///
/// These are needed mostly to allow Python hints to work, as hints are allowed to reference Cairo
/// identifiers (e.g. variables) by name, which would otherwise be lost during compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyIdentifier {
    /// Decorators of the identifier, used for functions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorators: Option<Vec<String>>,
    /// The Cairo type, used for type definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cairo_type: Option<String>,
    /// The fully-qualified name, used for struct definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// The list of members, used for struct definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<BTreeMap<String, LegacyIdentifierMember>>,
    /// The list of references, used for references.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<LegacyReference>>,
    /// The size in the number of field elements, used for struct definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The program counter, used for functions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc: Option<u64>,
    /// The fully-qualified name of the identifier that this identifier points to, used for
    /// aliases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Type of the identifier.
    pub r#type: String,
    /// Value of the identifier, used for constants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Box<serde_json::value::RawValue>>,
}

/// Data needed for tracking
/// [references](https://docs.cairo-lang.org/how_cairo_works/consts.html#references).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyReferenceManager {
    /// The list of references.
    pub references: Vec<LegacyReference>,
}

/// The legacy (Cairo 0) contract entrypoint offset, in either hexadecimal or numeric
/// representation.
///
/// This type is needed as the entrypoint offset field changed from hex string to number on 0.11.0.
/// The type allows serializing older contracts in their original forms.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
#[serde(untagged)]
pub enum LegacyEntrypointOffset {
    /// Offset with hexadecimal representation.
    U64AsHex(#[serde(with = "u64_hex")] u64),
    /// Offset with numeric representation.
    U64AsInt(u64),
}

/// Legacy (Cairo 0) instruction location for use in debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyInstructionLocation {
    /// The scopes from which the instruction is accessible.
    pub accessible_scopes: Vec<String>,
    // This field is serialized as `null` instead of skipped
    /// Data needed for tracking the allocation pointer.
    pub flow_tracking_data: Option<LegacyFlowTrackingData>,
    /// Physical code locations of hints in the source .
    pub hints: Vec<LegacyHintLocation>,
    /// Physical code location of the instruction in the source.
    pub inst: LegacyLocation,
}

/// Legacy (Cairo 0) struct member as part of a struct definition identifier. Used in
/// [`LegacyIdentifier`] for enabling hints to access identifiers by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyIdentifierMember {
    /// The Cairo type of this struct field.
    pub cairo_type: String,
    /// Offset of the field calculated as the total size of all the fields before this member in the
    /// number of field elements.
    pub offset: u64,
}

/// Cairo 0 [references](https://docs.cairo-lang.org/how_cairo_works/consts.html#references).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyReference {
    /// Data needed for tracking the allocation pointer.
    pub ap_tracking_data: LegacyApTrackingData,
    /// Program counter value.
    pub pc: u64,
    /// Value of the reference.
    pub value: String,
}

// Missing docs allowed as it's unclear what exactly how type works in the Cairo program.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyFlowTrackingData {
    pub ap_tracking: LegacyApTrackingData,
    pub reference_ids: BTreeMap<String, u64>,
}

/// Physical location of a legacy (Cairo 0) hint in source for use in debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyHintLocation {
    /// The physical location of the hint.
    pub location: LegacyLocation,
    /// The number of new lines following the "%{" symbol.
    pub n_prefix_newlines: u64,
}

/// The physical location in source of a certain code segment for use in debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyLocation {
    /// The ending column number.
    pub end_col: u64,
    /// The ending line number.
    pub end_line: u64,
    /// The file path or content.
    pub input_file: LegacyInputFile,
    /// Location of the parent instruction, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_location: Option<LegacyParentLocation>,
    /// The starting column number.
    pub start_col: u64,
    /// The starting line number.
    pub start_line: u64,
}

// Missing docs allowed as it's unclear what exactly how type works in the Cairo program.
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyApTrackingData {
    pub group: u64,
    pub offset: u64,
}

/// Input file path or content for use in debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct LegacyInputFile {
    /// Path to file in the file system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Full content of the file, typically for ephemeral files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Location of the parent instruction for use in debug info.
///
/// It's used (?) for generating human-readable stack traces.
#[derive(Debug, Clone)]
pub struct LegacyParentLocation {
    /// Location of the parent instruction.
    pub location: Box<LegacyLocation>,
    /// A human-readable remark usually in the form similar to "while trying to xxx".
    pub remark: String,
}

/// Legacy (Cairo 0) contract ABI item.
#[derive(Debug, Clone)]
pub enum RawLegacyAbiEntry {
    /// Constructor ABI entry.
    Constructor(RawLegacyConstructor),
    /// Function ABI entry.
    Function(RawLegacyFunction),
    /// Struct ABI entry.
    Struct(RawLegacyStruct),
    /// L1 handler ABI entry.
    L1Handler(RawLegacyL1Handler),
    /// Event ABI entry.
    Event(RawLegacyEvent),
}

/// Legacy (Cairo 0) contract ABI representation of a constructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLegacyConstructor {
    /// Inputs to the constructor.
    pub inputs: Vec<LegacyTypedParameter>,
    /// Name of the constructor.
    pub name: String,
    /// Outputs of the constructor.
    pub outputs: Vec<LegacyTypedParameter>,
}

/// Legacy (Cairo 0) contract ABI representation of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawLegacyFunction {
    /// Inputs to the function.
    pub inputs: Vec<LegacyTypedParameter>,
    /// Name of the function.
    pub name: String,
    /// Outputs of the function.
    pub outputs: Vec<LegacyTypedParameter>,
    /// State mutability of the function.
    ///
    /// Note that this is currently not enforced by the compiler. It's therefore only as accurate as
    /// the code author annotating them is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_mutability: Option<FunctionStateMutability>,
}

/// Legacy (Cairo 0) contract ABI representation of a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLegacyStruct {
    /// Fields of the struct.
    pub members: Vec<RawLegacyMember>,
    /// Name of the struct.
    pub name: String,
    /// Size of the struct in the number of field elements.
    pub size: u64,
}

/// Legacy (Cairo 0) contract ABI representation of an L1 handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLegacyL1Handler {
    /// Inputs to the L1 handler function.
    pub inputs: Vec<LegacyTypedParameter>,
    /// Name of the L1 handler function.
    pub name: String,
    /// Outputs of the L1 handler function.
    pub outputs: Vec<LegacyTypedParameter>,
}

/// Legacy (Cairo 0) contract ABI representation of an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLegacyEvent {
    /// Data of the events for the unindexed event fields.
    pub data: Vec<LegacyTypedParameter>,
    /// Keys of the events.
    ///
    /// This usually includes at least one element as the Starknet Keccak of the event name.
    /// Additional keys are used for indexed event fields, if any.
    pub keys: Vec<LegacyTypedParameter>,
    /// Name of the events.
    pub name: String,
}

/// Legacy (Cairo 0) contract ABI representation of a struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct RawLegacyMember {
    /// Name of the struct field.
    pub name: String,
    /// Total size of the fields in the struct before this field.
    pub offset: u64,
    /// Cairo type of the struct field.
    pub r#type: String,
}

struct ProgramForHintedHash;
struct AttributeForHintedHash;

impl From<LegacyEntrypointOffset> for u64 {
    fn from(value: LegacyEntrypointOffset) -> Self {
        match value {
            LegacyEntrypointOffset::U64AsHex(inner) | LegacyEntrypointOffset::U64AsInt(inner) => {
                inner
            }
        }
    }
}

impl From<LegacyEntrypointOffset> for Felt {
    fn from(value: LegacyEntrypointOffset) -> Self {
        match value {
            LegacyEntrypointOffset::U64AsHex(inner) | LegacyEntrypointOffset::U64AsInt(inner) => {
                inner.into()
            }
        }
    }
}

// Manually implementing this so we can put `type` at the end:
// https://github.com/xJonathanLEI/starknet-rs/issues/216
impl Serialize for RawLegacyAbiEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct TypedValue<'a, T> {
            #[serde(flatten)]
            value: &'a T,
            r#type: &'static str,
        }

        match self {
            Self::Constructor(value) => TypedValue::serialize(
                &TypedValue {
                    value: &value,
                    r#type: "constructor",
                },
                serializer,
            ),
            Self::Function(value) => TypedValue::serialize(
                &TypedValue {
                    value: &value,
                    r#type: "function",
                },
                serializer,
            ),
            Self::Struct(value) => TypedValue::serialize(
                &TypedValue {
                    value: &value,
                    r#type: "struct",
                },
                serializer,
            ),
            Self::L1Handler(value) => TypedValue::serialize(
                &TypedValue {
                    value: &value,
                    r#type: "l1_handler",
                },
                serializer,
            ),
            Self::Event(value) => TypedValue::serialize(
                &TypedValue {
                    value: &value,
                    r#type: "event",
                },
                serializer,
            ),
        }
    }
}

// We need to manually implement this because `raw_value` doesn't work with `tag`:
//   https://github.com/serde-rs/serde/issues/1183
impl<'de> Deserialize<'de> for RawLegacyAbiEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let temp_value = serde_json::Value::deserialize(deserializer)?;
        match &temp_value["type"] {
            serde_json::Value::String(type_str) => match &type_str[..] {
                "constructor" => Ok(Self::Constructor(
                    RawLegacyConstructor::deserialize(temp_value).map_err(|err| {
                        DeError::custom(format!("invalid constructor variant: {err}"))
                    })?,
                )),
                "function" => Ok(Self::Function(
                    RawLegacyFunction::deserialize(temp_value).map_err(|err| {
                        DeError::custom(format!("invalid function variant: {err}"))
                    })?,
                )),
                "struct" => Ok(Self::Struct(
                    RawLegacyStruct::deserialize(temp_value)
                        .map_err(|err| DeError::custom(format!("invalid struct variant: {err}")))?,
                )),
                "l1_handler" => Ok(Self::L1Handler(
                    RawLegacyL1Handler::deserialize(temp_value).map_err(|err| {
                        DeError::custom(format!("invalid l1_handler variant: {err}"))
                    })?,
                )),
                "event" => Ok(Self::Event(
                    RawLegacyEvent::deserialize(temp_value)
                        .map_err(|err| DeError::custom(format!("invalid event variant: {err}")))?,
                )),
                _ => Err(DeError::custom(format!(
                    "unknown ABI entry type: {type_str}"
                ))),
            },
            _ => Err(DeError::custom("invalid type field")),
        }
    }
}

impl LegacyContractClass {
    /// Computes the class hash of the legacy (Cairo 0) class.
    pub fn class_hash(&self) -> Result<Felt, ComputeClassHashError> {
        let mut elements = Vec::new();

        elements.push(API_VERSION);

        // Hashes external entry points
        elements.push({
            let mut buffer = Vec::new();
            for entrypoint in &self.entry_points_by_type.external {
                buffer.push(entrypoint.selector);
                buffer.push(entrypoint.offset.into());
            }
            compute_hash_on_elements(&buffer)
        });

        // Hashes L1 handler entry points
        elements.push({
            let mut buffer = Vec::new();
            for entrypoint in &self.entry_points_by_type.l1_handler {
                buffer.push(entrypoint.selector);
                buffer.push(entrypoint.offset.into());
            }
            compute_hash_on_elements(&buffer)
        });

        // Hashes constructor entry points
        elements.push({
            let mut buffer = Vec::new();
            for entrypoint in &self.entry_points_by_type.constructor {
                buffer.push(entrypoint.selector);
                buffer.push(entrypoint.offset.into());
            }
            compute_hash_on_elements(&buffer)
        });

        // Hashes builtins
        elements.push(compute_hash_on_elements(
            &self
                .program
                .builtins
                .iter()
                .map(|item| cairo_short_string_to_felt(item))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ComputeClassHashError::InvalidBuiltinName)?,
        ));

        // Hashes hinted_class_hash
        elements.push(self.hinted_class_hash()?);

        // Hashes bytecode
        elements.push(compute_hash_on_elements(&self.program.data));

        Ok(compute_hash_on_elements(&elements))
    }

    /// Computes the "hinted" class hash of the legacy (Cairo 0) class.
    ///
    /// This is known as the "hinted" hash as it isn't possible to directly calculate, and thus
    /// prove the correctness of, this hash, since it involves JSON serialization. Instead, this
    /// hash is always calculated outside of the Cairo VM, and then fed to the Cairo program as a
    /// hinted value.
    pub fn hinted_class_hash(&self) -> Result<Felt, ComputeClassHashError> {
        #[serde_as]
        #[derive(Serialize)]
        struct ContractArtifactForHash<'a> {
            abi: &'a Option<Vec<RawLegacyAbiEntry>>,
            #[serde_as(as = "ProgramForHintedHash")]
            program: &'a LegacyProgram,
        }

        let serialized = to_string_pythonic(&ContractArtifactForHash {
            abi: &self.abi,
            program: &self.program,
        })
        .map_err(|err| {
            ComputeClassHashError::Json(JsonError {
                message: format!("{err}"),
            })
        })?;

        Ok(starknet_keccak(serialized.as_bytes()))
    }

    /// Compresses the legacy (Cairo 0) class with gzip, as needed for class declaration.
    #[cfg(feature = "std")]
    pub fn compress(&self) -> Result<CompressedLegacyContractClass, CompressProgramError> {
        Ok(CompressedLegacyContractClass {
            program: self.program.compress()?,
            entry_points_by_type: self.entry_points_by_type.clone().into(),
            abi: self
                .abi
                .as_ref()
                .map(|abi| abi.iter().cloned().map(std::convert::Into::into).collect()),
        })
    }
}

impl LegacyProgram {
    /// Compresses the legacy (Cairo 0) program with gzip.
    #[cfg(feature = "std")]
    pub fn compress(&self) -> Result<Vec<u8>, CompressProgramError> {
        use std::io::Write;

        #[serde_as]
        #[derive(Serialize)]
        pub(crate) struct ProgramWithoutDebugInfo<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            attributes: &'a Option<Vec<LegacyAttribute>>,
            builtins: &'a Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compiler_version: &'a Option<String>,
            #[serde_as(as = "Vec<UfeHex>")]
            data: &'a Vec<Felt>,
            debug_info: Option<()>,
            hints: &'a BTreeMap<u64, Vec<LegacyHint>>,
            identifiers: &'a BTreeMap<String, LegacyIdentifier>,
            main_scope: &'a String,
            prime: &'a String,
            reference_manager: &'a LegacyReferenceManager,
        }

        let program_json = serde_json::to_string(&ProgramWithoutDebugInfo {
            attributes: &self.attributes,
            builtins: &self.builtins,
            compiler_version: &self.compiler_version,
            data: &self.data,
            debug_info: None,
            hints: &self.hints,
            identifiers: &self.identifiers,
            main_scope: &self.main_scope,
            prime: &self.prime,
            reference_manager: &self.reference_manager,
        })
        .map_err(|err| {
            CompressProgramError::Json(JsonError {
                message: format!("{err}"),
            })
        })?;

        // Use best compression level to optimize for payload size
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::best());
        gzip_encoder
            .write_all(program_json.as_bytes())
            .map_err(CompressProgramError::Io)?;

        gzip_encoder.finish().map_err(CompressProgramError::Io)
    }
}

impl Serialize for LegacyParentLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.location)?;
        seq.serialize_element(&self.remark)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for LegacyParentLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let temp_value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::Array(mut array) = temp_value {
            if array.len() != 2 {
                return Err(serde::de::Error::custom("length mismatch"));
            }

            let remark = array.pop().unwrap();
            let serde_json::Value::String(remark) = remark else {
                return Err(serde::de::Error::custom("unexpected value type"));
            };

            let location = array.pop().unwrap();
            let location = LegacyLocation::deserialize(location).map_err(|err| {
                serde::de::Error::custom(format!("unable to deserialize Location: {err}"))
            })?;

            Ok(Self {
                location: Box::new(location),
                remark,
            })
        } else {
            Err(serde::de::Error::custom("expected sequencer"))
        }
    }
}

impl SerializeAs<LegacyProgram> for ProgramForHintedHash {
    fn serialize_as<S>(source: &LegacyProgram, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[serde_as]
        #[derive(Serialize)]
        struct HashVo<'a> {
            #[serde(skip_serializing_if = "should_skip_attributes_for_hinted_hash")]
            #[serde_as(as = "Option<Vec<AttributeForHintedHash>>")]
            attributes: &'a Option<Vec<LegacyAttribute>>,
            builtins: &'a Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compiler_version: &'a Option<String>,
            #[serde_as(as = "Vec<UfeHex>")]
            data: &'a Vec<Felt>,
            debug_info: &'a Option<LegacyDebugInfo>,
            hints: &'a BTreeMap<u64, Vec<LegacyHint>>,
            identifiers: &'a BTreeMap<String, LegacyIdentifier>,
            main_scope: &'a String,
            prime: &'a String,
            reference_manager: &'a LegacyReferenceManager,
        }

        if source.compiler_version.is_some() {
            // Anything since 0.10.0 can be hashed directly. No extra overhead incurred.

            HashVo::serialize(
                &HashVo {
                    attributes: &source.attributes,
                    builtins: &source.builtins,
                    compiler_version: &source.compiler_version,
                    data: &source.data,
                    debug_info: &None,
                    hints: &source.hints,
                    identifiers: &source.identifiers,
                    main_scope: &source.main_scope,
                    prime: &source.prime,
                    reference_manager: &source.reference_manager,
                },
                serializer,
            )
        } else {
            // This is needed for backward compatibility with pre-0.10.0 contract artifacts.

            // We're cloning the entire `identifiers` here as a temporary patch. This is not
            // optimal, as it should technically be possible to avoid the cloning. This only
            // affects very old contract artifacts though.
            // TODO: optimize this to remove cloning.

            let patched_identifiers = source
                .identifiers
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_owned(),
                        LegacyIdentifier {
                            decorators: value.decorators.clone(),
                            cairo_type: value
                                .cairo_type
                                .as_deref()
                                .map(patch_legacy_cairo_type_owned),
                            full_name: value.full_name.clone(),
                            members: value.members.clone().map(|map| {
                                map.iter()
                                    .map(|(key, value)| {
                                        (
                                            key.to_owned(),
                                            LegacyIdentifierMember {
                                                cairo_type: patch_legacy_cairo_type_owned(
                                                    &value.cairo_type,
                                                ),
                                                offset: value.offset,
                                            },
                                        )
                                    })
                                    .collect()
                            }),
                            references: value
                                .references
                                .as_ref()
                                .map(|refs| refs.iter().map(patch_legacy_reference).collect()),
                            size: value.size,
                            pc: value.pc,
                            destination: value.destination.clone(),
                            r#type: value.r#type.clone(),
                            value: value.value.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();

            let patched_reference_manager = LegacyReferenceManager {
                references: source
                    .reference_manager
                    .references
                    .iter()
                    .map(patch_legacy_reference)
                    .collect(),
            };

            HashVo::serialize(
                &HashVo {
                    attributes: &source.attributes,
                    builtins: &source.builtins,
                    compiler_version: &source.compiler_version,
                    data: &source.data,
                    debug_info: &None,
                    hints: &source.hints,
                    identifiers: &patched_identifiers,
                    main_scope: &source.main_scope,
                    prime: &source.prime,
                    reference_manager: &patched_reference_manager,
                },
                serializer,
            )
        }
    }
}

/// Preserve the pre-0.10 legacy `" : "` spacing quirk without double-patching strings that are
/// already in that form. Returns the input unchanged when no patch is needed.
fn patch_legacy_cairo_type_owned(cairo_type: &str) -> String {
    patch_legacy_cairo_type(cairo_type).unwrap_or_else(|| cairo_type.to_owned())
}

/// Idempotent variant that returns `Some(patched)` only when the patch made a real change. Useful
/// for tests and for code that wants to know whether the input was already in legacy spacing form.
fn patch_legacy_cairo_type(cairo_type: &str) -> Option<String> {
    let bytes = cairo_type.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(cairo_type.len() + 4);
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        // Look for `": "` (colon followed by space) that is NOT already preceded by a space.
        // Bytewise indexing is fine: `:` and ` ` are ASCII, so they cannot collide with UTF-8
        // continuation bytes.
        if bytes[index] == b':'
            && index + 1 < bytes.len()
            && bytes[index + 1] == b' '
            && (index == 0 || bytes[index - 1] != b' ')
        {
            out.extend_from_slice(b" : ");
            index += 2;
            changed = true;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    if !changed {
        return None;
    }
    Some(String::from_utf8(out).expect("ASCII-only edits preserve UTF-8 validity"))
}

fn patch_legacy_reference(value: &LegacyReference) -> LegacyReference {
    LegacyReference {
        ap_tracking_data: value.ap_tracking_data.clone(),
        pc: value.pc,
        value: patch_legacy_cairo_type_owned(&value.value),
    }
}

impl SerializeAs<LegacyAttribute> for AttributeForHintedHash {
    fn serialize_as<S>(source: &LegacyAttribute, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct HashVo<'a> {
            #[serde(skip_serializing_if = "Vec::is_empty")]
            accessible_scopes: &'a Vec<String>,
            end_pc: &'a u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            flow_tracking_data: &'a Option<LegacyFlowTrackingData>,
            name: &'a String,
            start_pc: &'a u64,
            value: &'a String,
        }

        HashVo::serialize(
            &HashVo {
                accessible_scopes: &source.accessible_scopes,
                end_pc: &source.end_pc,
                flow_tracking_data: &source.flow_tracking_data,
                name: &source.name,
                start_pc: &source.start_pc,
                value: &source.value,
            },
            serializer,
        )
    }
}

impl From<RawLegacyEntryPoints> for LegacyEntryPointsByType {
    fn from(value: RawLegacyEntryPoints) -> Self {
        Self {
            constructor: value.constructor.into_iter().map(Into::into).collect(),
            external: value.external.into_iter().map(Into::into).collect(),
            l1_handler: value.l1_handler.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RawLegacyEntryPoint> for LegacyContractEntryPoint {
    fn from(value: RawLegacyEntryPoint) -> Self {
        Self {
            offset: value.offset.into(),
            selector: value.selector,
        }
    }
}

impl From<RawLegacyAbiEntry> for LegacyContractAbiEntry {
    fn from(value: RawLegacyAbiEntry) -> Self {
        match value {
            RawLegacyAbiEntry::Constructor(entry) => Self::Function(entry.into()),
            RawLegacyAbiEntry::Function(entry) => Self::Function(entry.into()),
            RawLegacyAbiEntry::Struct(entry) => Self::Struct(entry.into()),
            RawLegacyAbiEntry::L1Handler(entry) => Self::Function(entry.into()),
            RawLegacyAbiEntry::Event(entry) => Self::Event(entry.into()),
        }
    }
}

impl From<RawLegacyConstructor> for LegacyFunctionAbiEntry {
    fn from(value: RawLegacyConstructor) -> Self {
        Self {
            r#type: LegacyFunctionAbiType::Constructor,
            name: value.name,
            inputs: value.inputs,
            outputs: value.outputs,
            state_mutability: None,
        }
    }
}

impl From<RawLegacyFunction> for LegacyFunctionAbiEntry {
    fn from(value: RawLegacyFunction) -> Self {
        Self {
            r#type: LegacyFunctionAbiType::Function,
            name: value.name,
            inputs: value.inputs,
            outputs: value.outputs,
            state_mutability: value.state_mutability,
        }
    }
}

impl From<RawLegacyStruct> for LegacyStructAbiEntry {
    fn from(value: RawLegacyStruct) -> Self {
        Self {
            r#type: LegacyStructAbiType::Struct,
            name: value.name,
            size: value.size,
            members: value.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RawLegacyL1Handler> for LegacyFunctionAbiEntry {
    fn from(value: RawLegacyL1Handler) -> Self {
        Self {
            r#type: LegacyFunctionAbiType::L1Handler,
            name: value.name,
            inputs: value.inputs,
            outputs: value.outputs,
            state_mutability: None,
        }
    }
}

impl From<RawLegacyEvent> for LegacyEventAbiEntry {
    fn from(value: RawLegacyEvent) -> Self {
        Self {
            r#type: LegacyEventAbiType::Event,
            name: value.name,
            keys: value.keys,
            data: value.data,
        }
    }
}

impl From<RawLegacyMember> for LegacyStructMember {
    fn from(value: RawLegacyMember) -> Self {
        Self {
            name: value.name,
            r#type: value.r#type,
            offset: value.offset,
        }
    }
}

#[allow(clippy::ref_option)]
const fn should_skip_attributes_for_hinted_hash(value: &Option<Vec<LegacyAttribute>>) -> bool {
    match value {
        Some(value) => value.is_empty(),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::super::ContractArtifact;
    use super::*;

    #[derive(serde::Deserialize)]
    struct ContractHashes {
        // Regression fixtures only ship `class_hash`; the hinted hash is intermediate and is
        // implicitly exercised by the class hash assertion.
        #[serde(default)]
        hinted_class_hash: Option<String>,
        class_hash: String,
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_legacy_artifact_deser() {
        for raw_artifact in [
            include_str!("../../../test-data/contracts/cairo0/artifacts/oz_account.txt"),
            include_str!("../../../test-data/contracts/cairo0/artifacts/event_example.txt"),
            include_str!("../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.txt"),
            include_str!(
                "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/event_example.txt"
            ),
        ] {
            serde_json::from_str::<LegacyContractClass>(raw_artifact).unwrap();
        }
    }

    #[test]
    #[ignore = "https://github.com/xJonathanLEI/starknet-rs/issues/392"]
    fn test_legacy_artifact_deser_from_contract_artifact() {
        for raw_artifact in [
            include_str!("../../../test-data/contracts/cairo0/artifacts/oz_account.txt"),
            include_str!("../../../test-data/contracts/cairo0/artifacts/event_example.txt"),
            include_str!("../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.txt"),
            include_str!(
                "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/event_example.txt"
            ),
        ] {
            let direct_deser = serde_json::from_str::<LegacyContractClass>(raw_artifact).unwrap();
            let ContractArtifact::LegacyClass(deser_via_contract_artifact) =
                serde_json::from_str::<ContractArtifact>(raw_artifact).unwrap()
            else {
                panic!("unexpected artifact type")
            };

            // Class should be identical however it's deserialized
            assert_eq!(
                direct_deser.class_hash().unwrap(),
                deser_via_contract_artifact.class_hash().unwrap()
            );
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_contract_class_hash() {
        for (raw_artifact, raw_hashes) in [
            (
                include_str!("../../../test-data/contracts/cairo0/artifacts/oz_account.txt"),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/oz_account.hashes.json"
                ),
            ),
            (
                include_str!("../../../test-data/contracts/cairo0/artifacts/emoji.txt"),
                include_str!("../../../test-data/contracts/cairo0/artifacts/emoji.hashes.json"),
            ),
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.hashes.json"
                ),
            ),
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/braavos_proxy.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/braavos_proxy.hashes.json"
                ),
            ),
            // Regression: `abi: null` must be preserved verbatim in the hinted hash payload.
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0x371b5f7c5517d84205365a87f02dcef230efa7b4dd91a9e4ba7e04c5b69d69b.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0x371b5f7c5517d84205365a87f02dcef230efa7b4dd91a9e4ba7e04c5b69d69b.hashes.json"
                ),
            ),
            // Regression: legacy `" : "` spacing must be applied to `references[*].value`.
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0x6dc10e7703c1b63e0b5a4e8e7842293d3255fd4e53d4e730adf435c3dffabb.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0x6dc10e7703c1b63e0b5a4e8e7842293d3255fd4e53d4e730adf435c3dffabb.hashes.json"
                ),
            ),
            // Regression: strings already in `" : "` form must not be double-patched.
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0xa0cb53aaa37a4d377736e7e98c1a96b5168d75e3705f30fb09e6d2cbd7d5e3.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/0xa0cb53aaa37a4d377736e7e98c1a96b5168d75e3705f30fb09e6d2cbd7d5e3.hashes.json"
                ),
            ),
        ] {
            let artifact = serde_json::from_str::<LegacyContractClass>(raw_artifact).unwrap();
            let computed_hash = artifact.class_hash().unwrap();

            let hashes: ContractHashes = serde_json::from_str(raw_hashes).unwrap();
            let expected_hash = Felt::from_hex(&hashes.class_hash).unwrap();

            assert_eq!(computed_hash, expected_hash);
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_contract_hinted_class_hash() {
        for (raw_artifact, raw_hashes) in [
            (
                include_str!("../../../test-data/contracts/cairo0/artifacts/oz_account.txt"),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/oz_account.hashes.json"
                ),
            ),
            (
                include_str!("../../../test-data/contracts/cairo0/artifacts/emoji.txt"),
                include_str!("../../../test-data/contracts/cairo0/artifacts/emoji.hashes.json"),
            ),
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.11.0/oz_account.hashes.json"
                ),
            ),
            (
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/braavos_proxy.txt"
                ),
                include_str!(
                    "../../../test-data/contracts/cairo0/artifacts/pre-0.10.0/braavos_proxy.hashes.json"
                ),
            ),
        ] {
            let artifact = serde_json::from_str::<LegacyContractClass>(raw_artifact).unwrap();
            let computed_hash = artifact.hinted_class_hash().unwrap();

            let hashes: ContractHashes = serde_json::from_str(raw_hashes).unwrap();
            let expected_hash = Felt::from_hex(hashes.hinted_class_hash.as_ref().unwrap()).unwrap();

            assert_eq!(computed_hash, expected_hash);
        }
    }

    #[test]
    fn test_patch_legacy_cairo_type() {
        // No `": "` substring — no patch.
        assert_eq!(patch_legacy_cairo_type("felt"), None);
        // Plain case — insert leading space.
        assert_eq!(
            patch_legacy_cairo_type("felt: T").as_deref(),
            Some("felt : T")
        );
        // Already patched — no-op (idempotent).
        assert_eq!(patch_legacy_cairo_type("felt : T"), None);
        // Mixed: only the unpatched occurrence is patched.
        assert_eq!(
            patch_legacy_cairo_type("a : T, b: U").as_deref(),
            Some("a : T, b : U")
        );
        // Multiple unpatched occurrences in one string.
        assert_eq!(
            patch_legacy_cairo_type("(a: T, b: U)").as_deref(),
            Some("(a : T, b : U)")
        );
        // Colon without trailing space is left alone.
        assert_eq!(patch_legacy_cairo_type("a:T"), None);
        // Leading colon at index 0 still gets patched (no preceding space to dedupe against).
        assert_eq!(patch_legacy_cairo_type(": T").as_deref(), Some(" : T"));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_artifact_json_equivalence() {
        // Removes '\n' or "\r\n" at the end
        let original_text =
            include_str!("../../../test-data/contracts/cairo0/artifacts/oz_account.txt");
        let original_text = original_text
            .trim_end_matches("\r\n")
            .trim_end_matches('\n');

        let artifact = serde_json::from_str::<LegacyContractClass>(original_text).unwrap();
        let serialized = serde_json::to_string(&artifact).unwrap();

        assert_eq!(original_text, serialized);
    }
}
