use std::fmt::{self, Display};

use crate::dgc::{DigitalGreenCertificate, Verified};

impl Display for DigitalGreenCertificate<Verified<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cert = &self.hcert_payload().hcert[&1];
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
            writeln!(f, "Vaccine data:").ok();

            writeln!(
                f,
                "\tTargeted disease: {}",
                translate_disease(vaccine_data.tg)
            )
            .ok();

            writeln!(
                f,
                "\tName: {}",
                translate_medicinal_product(vaccine_data.mp)
            )
            .ok();
            writeln!(f, "\tType: {}", translate_vaccine_type(vaccine_data.vp)).ok();
            writeln!(
                f,
                "\tManufacturer : {}",
                translate_marketing_org(vaccine_data.ma)
            )
            .ok();

            writeln!(
                f,
                "\tShot {}/{} done {}.",
                &vaccine_data.dn, &vaccine_data.sd, &vaccine_data.dt
            )
            .ok();

            writeln!(
                f,
                "Certificate issued by {} ({}):",
                &vaccine_data.is, &vaccine_data.co
            )
            .ok();
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

/*pub fn to_human_readable(dgc: &DigitalGreenCertificate) {

    let cert = &dgc.hcert[&1];
    let person = &cert.nam;

    println!("Person: {} {} (born {})", person.sn, person.gn, cert.dob);

    if let Some([vaccine_data]) = &cert.v {

        println!("Targeted disease: {}", translate_disease(&vaccine_data.tg));
        println!("");

        println!("Vaccine data:");
        println!("\tName: {}", translate_medicinal_product(&vaccine_data.mp));
        println!("\tType: {}", translate_vaccine_type(&vaccine_data.vp));
        println!("\tManufacturer : {}", translate_marketing_org(&vaccine_data.ma));

        println!("");
        println!("Shot {}/{} done {}.", &vaccine_data.dn, &vaccine_data.sd, &vaccine_data.dt);

        println!("Certificate issued by {} ({})", &vaccine_data.is, &vaccine_data.co)
    }
    else {
        print!("not found!");
    }



}*/

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
        "CVnCoV" => "CVnCoV",
        "NVX-CoV2373" => "NVX-CoV2373",
        "Sputnik-V" => "Sputnik V",
        "Convidecia" => "Convidecia",
        "EpiVacCorona" => "EpiVacCorona",
        "BBIBP-CorV" => "BBIBP-CorV",
        "CoronaVac" => "CoronaVac",
        "Covaxin" => "Covaxin (also known as BBV152 A, B, C)",

        "Inactivated-SARS-CoV-2-Vero-Cell" => "Inactivated SARS-CoV-2 (Vero Cell)",

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
