//! `gen-certs`: a private CA, one server certificate and one client certificate.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

/// What was written.
#[derive(Debug, Clone)]
pub struct Generated {
    /// The CA certificate: the server's client CA and the client's trust anchor.
    pub ca_cert: PathBuf,
    /// The CA's private key. Move it offline.
    pub ca_key: PathBuf,
    /// The server certificate.
    pub server_cert: PathBuf,
    /// The server key.
    pub server_key: PathBuf,
    /// The client certificate.
    pub client_cert: PathBuf,
    /// The client key.
    pub client_key: PathBuf,
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn name(common: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common);
    dn
}

/// Makes the files in `out` (made 0700 if missing). Refuses to overwrite any of them: nothing is
/// written then. Leaf certificates last one year, the CA five; leaves are not CA capable and have
/// the one extended key usage they need.
pub fn generate(out: &Path, server_name: &str, client_name: &str) -> Result<Generated, String> {
    if server_name.is_empty() || client_name.is_empty() {
        return Err("a name is empty".to_string());
    }
    let files = Generated {
        ca_cert: out.join("ca.pem"),
        ca_key: out.join("ca.key"),
        server_cert: out.join("server.pem"),
        server_key: out.join("server.key"),
        client_cert: out.join("client.pem"),
        client_key: out.join("client.key"),
    };
    let all = [
        &files.ca_cert,
        &files.ca_key,
        &files.server_cert,
        &files.server_key,
        &files.client_cert,
        &files.client_key,
    ];
    if let Some(existing) = all.iter().find(|p| p.symlink_metadata().is_ok()) {
        return Err(format!(
            "{} exists already: refusing to overwrite",
            existing.display()
        ));
    }
    if !out.is_dir() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(out)
            .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    }
    let started = OffsetDateTime::now_utc() - Duration::days(1);
    let err = |e: rcgen::Error| format!("certificate: {e}");

    let ca_key = KeyPair::generate().map_err(err)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
    ca_params.distinguished_name = name("menzil-relay-admin CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = started;
    ca_params.not_after = started + Duration::days(5 * 365 + 1);
    let ca_cert = ca_params.self_signed(&ca_key).map_err(err)?;
    let issuer = Issuer::new(ca_params, &ca_key);

    let leaf = |common: &str, sans: Vec<SanType>, usage: ExtendedKeyUsagePurpose| {
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        params.distinguished_name = name(common);
        params.subject_alt_names = sans;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        params.not_before = started;
        params.not_after = started + Duration::days(366);
        let key = KeyPair::generate().map_err(err)?;
        let cert = params.signed_by(&key, &issuer).map_err(err)?;
        Ok::<_, String>((cert, key))
    };
    let san = |text: &str| -> Result<SanType, String> {
        match text.parse::<IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => Ok(SanType::DnsName(text.try_into().map_err(err)?)),
        }
    };
    let mut server_sans = vec![san(server_name)?];
    if server_name != "127.0.0.1" {
        server_sans.push(SanType::IpAddress("127.0.0.1".parse().expect("literal")));
    }
    let (server_cert, server_key) = leaf(
        server_name,
        server_sans,
        ExtendedKeyUsagePurpose::ServerAuth,
    )?;
    let (client_cert, client_key) = leaf(
        client_name,
        vec![san(client_name)?],
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;

    write_new(&files.ca_cert, ca_cert.pem().as_bytes(), 0o644)?;
    write_new(&files.ca_key, ca_key.serialize_pem().as_bytes(), 0o600)?;
    write_new(&files.server_cert, server_cert.pem().as_bytes(), 0o644)?;
    write_new(
        &files.server_key,
        server_key.serialize_pem().as_bytes(),
        0o600,
    )?;
    write_new(&files.client_cert, client_cert.pem().as_bytes(), 0o644)?;
    write_new(
        &files.client_key,
        client_key.serialize_pem().as_bytes(),
        0o600,
    )?;
    Ok(files)
}
