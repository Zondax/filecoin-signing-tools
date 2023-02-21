pub mod address {
    use fvm_shared::address::{Address, Network};
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(address: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = address.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // If mainnet address
        if s.starts_with("f") {
            return Network::Mainnet
                .parse_address(&s)
                .map_err(de::Error::custom);
        } else {
            return Network::Testnet
                .parse_address(&s)
                .map_err(de::Error::custom);
        }
    }
}

pub mod cid {
    use cid::Cid;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(cid: &Cid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = cid.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Cid::from_str(&s).map_err(de::Error::custom)
    }
}

pub mod rawbytes {
    use base64::{decode, encode};
    use fvm_ipld_encoding::RawBytes;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(raw: &RawBytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = encode(raw.bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RawBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = decode(s).map_err(de::Error::custom)?;
        Ok(RawBytes::new(raw))
    }
}

pub mod vec_address {
    use fvm_shared::address::{Address, Network};
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(addresses: &Vec<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut result = vec![];

        for a in addresses {
            let a: &Address = a;
            let s = a.to_string();
            result.push(s);
        }

        serializer.collect_seq(result)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let a: Vec<String> = Vec::deserialize(deserializer)?;
        let mut result: Vec<Address> = Vec::new();

        for s in a {
            let s: String = s;
            let network: Network;
            // If mainnet address
            if s.starts_with("f") {
                network = Network::Mainnet;
            } else {
                network = Network::Testnet;
            }
            let address = network.parse_address(&s).map_err(de::Error::custom)?;
            result.push(address);
        }

        Ok(result)
    }
}

pub mod option_address {
    use super::address;
    use fvm_shared::address::Address;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(address: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct W<'a>(#[serde(with = "address")] &'a Address);

        match address {
            Some(a) => serializer.serialize_some(&W(a)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct W(#[serde(with = "address")] Address);

        Ok(Option::deserialize(deserializer)?.map(|W(inner)| inner))
    }
}

pub mod tokenamount {
    use fvm_shared::{bigint::BigInt, econ::TokenAmount};
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(token_amount: &TokenAmount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = token_amount.atto().to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TokenAmount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let amount = BigInt::from_str(&s).map_err(de::Error::custom)?;

        Ok(TokenAmount::from_atto(amount))
    }
}

pub mod bigint {
    use fvm_shared::bigint::BigInt;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(token_amount: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = token_amount.to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigInt::from_str(&s).map_err(de::Error::custom)
    }
}

pub mod serde_base64_vector {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(v))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::decode(s).map_err(serde::de::Error::custom)
    }
}

pub mod option_signature {
    use super::super::signature::SignatureAPI;
    use fvm_shared::crypto::signature::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(signature: &Option<Signature>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct W<'a>(#[serde(with = "SignatureAPI")] &'a Signature);

        match signature {
            Some(s) => serializer.serialize_some(&W(&s)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Signature>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct W(#[serde(with = "SignatureAPI")] Signature);

        Ok(Option::deserialize(deserializer)?.map(|W(inner)| inner))
    }
}
