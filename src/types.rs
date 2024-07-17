use alloy_primitives::bytes::BufMut;
use alloy_rlp::{Decodable, Encodable};
use secp256k1::ecdh::SharedSecret;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Default)]
pub struct B128Z(pub Zeroizing<[u8; 16]>);

#[derive(Clone, Debug, Default)]
pub struct B256Z(pub Zeroizing<[u8; 32]>);

#[derive(Clone, Debug)]
pub struct SharedSecretZ(pub SharedSecret);

impl B128Z {
    pub fn new(value: [u8; 16]) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl B256Z {
    pub fn new(value: [u8; 32]) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn bitxor(&self, other: &[u8]) -> Self {
        let mut result = self.clone();
        result.0.iter_mut().zip(other).for_each(|(one, two)| {
            *one ^= *two;
        });

        result
    }
}

impl SharedSecretZ {
    pub fn new(value: SharedSecret) -> Self {
        Self(value)
    }
}

impl Drop for SharedSecretZ {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl Decodable for B256Z {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::new(<[u8; 32]>::decode(buf)?))
    }
}

impl Encodable for B256Z {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.as_ref().encode(out);
    }
}

impl AsRef<[u8]> for B256Z {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
