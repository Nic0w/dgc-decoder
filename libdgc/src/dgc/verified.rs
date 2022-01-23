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

    pub(crate) fn inner(&self) -> &CertificateData {
        &self.hcert_payload().hcert[&1]
    }

    pub fn person(&self) -> &Person {
        &self.inner().nam
     }
 
     pub fn vaccine_data(&self) -> Option<&Vaccine> {
        self.inner().v
            .as_ref()
            .and_then(|v| v.first())
     }
 
     pub fn test_data(&self) -> Option<&Test> {
        self.inner().t
            .as_ref()
            .and_then(|t| t.first())
     }
 
     pub fn recovery_data(&self) -> Option<&Recovery> {
        self.inner().r
            .as_ref()
            .and_then(|r| r.first())
     }
}