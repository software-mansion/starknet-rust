use alloc::vec::Vec;
use core::{fmt, marker::PhantomData, mem};

use serde::{
    Deserializer, Serializer,
    de::{SeqAccess, Visitor},
};
use serde_with::{DeserializeAs, SerializeAs, de::DeserializeAsWrap};

/// Applies a Serde adapter to each element of a vector.
#[derive(Debug)]
pub struct VecAs<Adapter>(PhantomData<Adapter>);

impl<T, Adapter> SerializeAs<Vec<T>> for VecAs<Adapter>
where
    Adapter: SerializeAs<T>,
{
    fn serialize_as<S>(values: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <[Adapter]>::serialize_as(values.as_slice(), serializer)
    }
}

impl<'de, T, Adapter> DeserializeAs<'de, Vec<T>> for VecAs<Adapter>
where
    Adapter: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor<T, Adapter>(PhantomData<(T, Adapter)>);

        impl<'de, T, Adapter> Visitor<'de> for VecVisitor<T, Adapter>
        where
            Adapter: DeserializeAs<'de, T>,
        {
            type Value = Vec<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Bound the initial allocation when a deserializer supplies an untrusted length.
                let capacity = seq
                    .size_hint()
                    .unwrap_or(0)
                    .min(1024 * 1024 / mem::size_of::<T>().max(1));
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = seq.next_element::<DeserializeAsWrap<T, Adapter>>()? {
                    values.push(value.into_inner());
                }
                Ok(values)
            }
        }

        deserializer.deserialize_seq(VecVisitor::<T, Adapter>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serde::unsigned_field_element::UfeHex, types::Felt};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct FeltList(#[serde_as(as = "VecAs<UfeHex>")] Vec<Felt>);

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn felt_list_wire_format() {
        let list = FeltList(alloc::vec![Felt::ONE, Felt::TWO]);
        let json = r#"["0x1","0x2"]"#;
        assert_eq!(serde_json::to_string(&list).unwrap(), json);
        assert_eq!(serde_json::from_str::<FeltList>(json).unwrap(), list);

        let mut binary = Vec::from(2_u64.to_le_bytes());
        for felt in &list.0 {
            binary.extend_from_slice(&32_u64.to_le_bytes());
            binary.extend_from_slice(&felt.to_bytes_be());
        }
        assert_eq!(bincode::serialize(&list).unwrap(), binary);
        assert_eq!(bincode::deserialize::<FeltList>(&binary).unwrap(), list);
    }
}
