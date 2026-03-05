/// Serializing and deserializing [`Vec<u64>`] as a base64-encoded string.
///
/// Each `u64` is encoded as 4 little-endian bytes (truncated to `u32`),
/// matching the Starknet proof binary format expected by Pathfinder.
pub mod base64_u64_vec {
    use alloc::{fmt::Formatter, format, vec::Vec};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserializer, Serializer, de::Visitor};

    struct Base64U64Visitor;

    /// Serializes `Vec<u64>` as a base64 string (each element as 4 LE bytes).
    pub fn serialize<S>(value: &Vec<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = value.iter().flat_map(|v| (*v as u32).to_le_bytes()).collect();
        serializer.serialize_str(&STANDARD.encode(&bytes))
    }

    /// Deserializes `Vec<u64>` from a base64 string (each 4 bytes as one LE u32 → u64).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64U64Visitor)
    }

    impl Visitor<'_> for Base64U64Visitor {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> alloc::fmt::Result {
            write!(formatter, "a base64-encoded string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let bytes = STANDARD
                .decode(v)
                .map_err(|err| serde::de::Error::custom(format!("invalid base64 string: {err}")))?;
            if bytes.len() % 4 != 0 {
                return Err(serde::de::Error::custom(format!(
                    "proof base64 decoded length {} is not a multiple of 4",
                    bytes.len()
                )));
            }
            Ok(bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64).collect())
        }
    }
}

/// Serializing and deserializing [`Option<Vec<u64>>`] as an optional base64 string.
pub mod option_base64_u64_vec {
    use alloc::vec::Vec;

    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes `Option<Vec<u64>>` as an optional base64 string.
    pub fn serialize<S>(value: &Option<Vec<u64>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => super::base64_u64_vec::serialize(v, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes `Option<Vec<u64>>` from an optional base64 string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u64>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<&str> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                use alloc::format;
                use base64::{Engine, engine::general_purpose::STANDARD};
                let bytes = STANDARD
                    .decode(s)
                    .map_err(|err| serde::de::Error::custom(format!("invalid base64 string: {err}")))?;
                if bytes.len() % 4 != 0 {
                    return Err(serde::de::Error::custom(format!(
                        "proof base64 decoded length {} is not a multiple of 4",
                        bytes.len()
                    )));
                }
                Ok(Some(
                    bytes
                        .chunks_exact(4)
                        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64)
                        .collect(),
                ))
            }
            None => Ok(None),
        }
    }
}

/// Serializing and deserializing [`Vec<u8>`] with base64 encoding.
pub mod base64 {
    use alloc::{fmt::Formatter, format, vec::Vec};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserializer, Serializer, de::Visitor};

    struct Base64Visitor;

    /// Serializes [`Vec<u8>`] as base64 string.
    pub fn serialize<S, T>(value: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<Vec<u8>>,
    {
        serializer.serialize_str(&STANDARD.encode(value.as_ref()))
    }

    /// Deserializes [`Vec<u8>`] from base64 string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Base64Visitor)
    }

    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> alloc::fmt::Result {
            write!(formatter, "string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            STANDARD
                .decode(v)
                .map_err(|err| serde::de::Error::custom(format!("invalid base64 string: {err}")))
        }
    }
}
