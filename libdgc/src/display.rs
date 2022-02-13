use std::fmt::{self, Display};

use crate::{
    dgc::{DigitalGreenCertificate, Verified},
    hcert::{HCertPayload, Test, Vaccine, Recovery},
};

impl Display for Vaccine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Vaccine data:").ok();

        writeln!(f, "\tTargeted disease: {}", translate_disease(self.tg)).ok();

        writeln!(f, "\tName: {}", translate_medicinal_product(self.mp)).ok();
        writeln!(f, "\tType: {}", translate_vaccine_type(self.vp)).ok();
        writeln!(f, "\tManufacturer : {}", translate_marketing_org(self.ma)).ok();

        writeln!(f, "\tShot {}/{} done {}.", &self.dn, &self.sd, &self.dt).ok();

        writeln!(f, "Certificate issued by {} ({}):", &self.is, &self.co)
    }
}

impl Display for Test<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Test data:").ok();

        writeln!(f, "\tTargeted disease: {}", translate_disease(self.tg)).ok();

        writeln!(f, "\tTest type: {}", translate_test_type(self.tt)).ok();

        match (self.nm, self.ma) {
            (Some(nm), None) => writeln!(f, "\tTest name: {}", nm).ok(),

            (None, Some(ma)) =>
            //TODO: translate that field
            {
                writeln!(f, "\tTest device: {}", ma).ok()
            }

            invalid => panic!("Invalid combination: {:?}", invalid),
        };

        writeln!(f, "\tSample collection date: {}", self.sc).ok();

        writeln!(f, "\tTest result: {}", translate_test_result(self.tr)).ok();

        writeln!(f, "\tTest facility: {}", self.tc).ok();

        writeln!(f, "\tTest id: {}", self.ci).ok();

        writeln!(f, "Certificate issued by {} ({}):", &self.is, &self.co)
    }
}

impl Display for Recovery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Recovery data:").ok();

        writeln!(f, "\tTargeted disease: {}", translate_disease(self.tg)).ok();

        writeln!(f, "\tDate of first NAAT positive test: {}", self.fr).ok();

        writeln!(f, "\tCertificate valid from: {}", self.df).ok();

        writeln!(f, "\tCertificate valid until: {}", self.du).ok();

        writeln!(f, "\tCertificate id: {}", self.ci).ok();

        writeln!(f, "Certificate issued by {} ({}):", &self.is, &self.co)
    }
}

impl Display for HCertPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cert = &self.hcert[&1];
        let person = &cert.nam;
        let dob = &cert.dob;

        writeln!(
            f,
            "Digital Green Certificate for {} {} (born {}):",
            person.sn, person.gn, dob
        )
        .ok();

        let days = self.expiring_at() - self.issued_at();

        if let Some([vaccine_data]) = &cert.v {
            vaccine_data.fmt(f).ok();
        } else if let Some([test_data]) = &cert.t {
            test_data.fmt(f).ok();
        } else if let Some([recovery_data]) = &cert.r {
            recovery_data.fmt(f).ok();
        }

        writeln!(
            f,
            "\tIssued at: {};\n\tExpiring at: {};\n\tDuration: {} days",
            self.issued_at(),
            self.expiring_at(),
            days.num_days()
        )
        .ok();

        writeln!(f)
    }
}

impl Display for DigitalGreenCertificate<Verified<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hcert_payload().fmt(f)
    }
}

pub fn translate_disease(tg: &str) -> &str {
    match tg {
        "840539006" => "COVID-19",

        _ => tg,
    }
}

pub fn translate_vaccine_type(vp: &str) -> &str {
    match vp {
        "1119305005" => "SARS-CoV2 antigen vaccine",
        "1119349007" => "SARS-CoV2 mRNA vaccine",
        "J07BX03" => "covid-19 vaccines",
        _ => vp,
    }
}

pub fn translate_medicinal_product(mp: &str) -> &str {
    match mp {
        "EU/1/20/1528" => "Comirnaty",
        "EU/1/20/1507" => "COVID-19 Vaccine Moderna",
        "EU/1/21/1529" => "Vaxzevria",
        "EU/1/20/1525" => "COVID-19 Vaccine Janssen",

        "Covaxin" => "Covaxin (also known as BBV152 A, B, C)",
        "Inactivated-SARS-CoV-2-Vero-Cell" => "Inactivated SARS-CoV-2 (Vero Cell)",

        "CVnCoV" | "NVX-CoV2373" | "Sputnik-V" | "Convidecia" | "EpiVacCorona" | "BBIBP-CorV" | "CoronaVac" => mp,

        _ => mp,
    }
}

pub fn translate_marketing_org(ma: &str) -> &str {
    match ma {
        "ORG-100001699" => "AstraZeneca AB",
        "ORG-100030215" => "Biontech Manufacturing GmbH",
        "ORG-100001417" => "Janssen-Cilag International",
        "ORG-100031184" => "Moderna Biotech Spain S.L.",
        "ORG-100006270" => "Curevac AG",
        "ORG-100013793" => "CanSino Biologics",
        "ORG-100020693" => "China Sinopharm International Corp. - Beijing location",
        "ORG-100010771" => "Sinopharm Weiqida Europe Pharmaceutical s.r.o. - Prague location",
        "ORG-100024420" => {
            "Sinopharm Zhijun (Shenzhen) Pharmaceutical Co. Ltd. - Shenzhen location"
        }
        "ORG-100032020" => "Novavax CZ AS",
        "Gamaleya-Research-Institute" => "Gamaleya Research Institute",
        "Vector-Institute" => "Vector Institute",
        "Sinovac-Biotech" => "Sinovac Biotech",
        "Bharat-Biotech" => "Bharat Biotech",

        _ => ma,
    }
}

pub fn translate_test_type(tt: &str) -> &str {
    match tt {
        "LP6464-4" => "Nucleic acid amplification with probe detection",
        "LP217198-3" => "Rapid immunoassay",

        _ => tt,
    }
}

pub fn translate_test_result(tr: &str) -> &str {
    match tr {
        "260415000" => "Not detected",
        "260373001" => "Detected",
        _ => tr,
    }
}
