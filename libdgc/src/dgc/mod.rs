use std::marker::PhantomData;

use crate::{cose::COSE_Sign1, hcert::HCertPayload};

mod error;
mod raw;
mod decoded;
mod verified;

pub struct Raw<'r> {
    buffer: Vec<u8>,
    __ : PhantomData<&'r ()>
}

pub struct Decoded<'buf> {
    cose_msg: COSE_Sign1<'buf>,
}
pub struct Verified<'sign1> {
    pub hcert_payload: HCertPayload<'sign1>,
}
pub struct Invalid;

pub trait State {}
impl<'r> State for Raw<'r> {}
impl<'b> State for Decoded<'b> {}
impl<'s> State for Verified<'s> {}

pub struct DigitalGreenCertificate<T: State> {
    state: T,
}