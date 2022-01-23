use chrono::{DateTime, Utc, TimeZone};

use crate::hcert::{HCertPayload, CertificateData, Person, Vaccine, Test, Recovery};

use super::{DigitalGreenCertificate, Verified};



impl<'sign1> DigitalGreenCertificate<Verified<'sign1>> {

    pub fn hcert_payload(&self) -> &HCertPayload {
        &self.state.hcert_payload
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.hcert_payload().iat as i64, 0)
    }

    pub fn expiring_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.hcert_payload().exp as i64, 0)
    }

    pub fn signature_issuer(&self) -> &str {
        self.hcert_payload().iss
    }
}

impl<'s> DigitalGreenCertificate<Verified<'s>> {
    pub(crate) fn inner(&self) -> &CertificateData {
        &self.hcert_payload().hcert[&1]
    }

    pub fn person(&self) -> &Person {
       &self.inner().nam
    }

    pub fn vaccine_data(&self) -> &Option<[Vaccine; 1]> {
        &self.inner().v
    }

    pub fn test_data(&self) -> &Option<[Test; 1]> {
        &self.inner().t
    }

    pub fn recovery_data(&self) -> &Option<[Recovery; 1]> {
        &self.inner().r
    }
}