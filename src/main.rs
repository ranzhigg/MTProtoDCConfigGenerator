use aes::Aes256;
use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flate2::read::GzDecoder;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{Rng, RngCore};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type GeneratorResult<T> = Result<T, String>;

const TIMEOUT: Duration = Duration::from_secs(10);
const API_LAYER: i32 = 227;
const API_ID: i32 = 2040;
const RSA_FINGERPRINT: i64 = 0x0bc3_5f35_09f7_b7a5;
const MAX_PACKET_WORDS: usize = 1024 * 1024;
const DC_OPTION_FLAG_IPV6: i32 = 1 << 0;
const DC_OPTION_FLAG_MEDIA_ONLY: i32 = 1 << 1;
const DC_OPTION_FLAG_TCPO_ONLY: i32 = 1 << 2;
const DC_OPTION_FLAG_CDN: i32 = 1 << 3;
const DC_OPTION_FLAG_STATIC: i32 = 1 << 4;
const DC_OPTION_FLAG_SECRET: i32 = 1 << 10;
const BACKUP_CONFIG_URL: &str = "https://dns.google.com/resolve?name=apv3.stel.com&type=16";

// Production seed endpoints shipped by the official iOS and Desktop clients.
// These are useful even when a particular help.getConfig response omits them.
const BOOTSTRAP_ENDPOINTS: &[(i32, &str, u16)] = &[
    (1, "149.154.175.50", 443),
    (1, "2001:b28:f23d:f001::a", 443),
    (2, "149.154.167.50", 443),
    (2, "149.154.167.51", 443),
    (2, "95.161.76.100", 443),
    (2, "2001:67c:4e8:f002::a", 443),
    (3, "149.154.175.100", 443),
    (3, "2001:b28:f23d:f003::a", 443),
    (4, "149.154.167.91", 443),
    (4, "2001:67c:4e8:f004::a", 443),
    (5, "149.154.171.5", 443),
    (5, "2001:b28:f23f:f005::a", 443),
];

const TELEGRAM_RSA_KEY_DER_BASE64: &str = concat!(
    "MIIBCgKCAQEAruw2yP/BCcsJliRoW5eBVBVle9dtjJw+OYED160Wybum9SXtBBLX",
    "riwt4rROd9csv0t0OHCaTmRqBcQ0J8fxhN6/cpR1GWgOZRUAiQxoMnlt0R93LCX/",
    "j1dnVa/gVbCjdSxpbrfY2g2L4frzjJvdl84Kd9ORYjDEAyFnEA7dD556OptgLQQ2",
    "e2iVNq8NZLYTzLp5YpOdO1doK+ttrltggTCy5SrKeLoCPPbOgGsdxJxyz5KKcZnS",
    "Lj16yE5HvJQn0CNpRdENvRUXe6tBP78O39oJ8BTHp9oIjd6XWXAsp2CvK45Ol8wF",
    "XGF710w9lwCGNbmNxNYhtIkdqfsEcwR5JwIDAQAB"
);

const BACKUP_CONFIG_RSA_KEY_DER_BASE64: &str = concat!(
    "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF",
    "fOBUlfXUEvM/fnKCpF46VkAftlb4VuPDeQSS/ZxZYEGqHaywlroVnXHIjgqoxiAd",
    "192xRGreuXIaUKmkwlM9JID9WS2jUsTpzQ91L8MEPLJ/4zrBwZua8W5fECwCCh2c",
    "9G5IzzBm+otMS/YKwmR1olzRCyEkyAEjXWqBI9Ftv5eG8m0VkBzOG655WIYdyV0H",
    "fDK/NWcvGqa0w/nriMD6mDjKOryamw0OP9QuYgMN0C9xMW9y8SmP4h92OAWodTYg",
    "Y1hZCxdv6cs5UnW9+PWvS+WIbkh+GaWYxwIDAQAB"
);

fn append_i32(data: &mut Vec<u8>, value: i32) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn append_i64(data: &mut Vec<u8>, value: i64) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn append_tl_bytes(data: &mut Vec<u8>, value: &[u8]) -> GeneratorResult<()> {
    let prefix_length;
    if value.len() < 254 {
        data.push(value.len() as u8);
        prefix_length = 1;
    } else if value.len() <= 0x00ff_ffff {
        data.push(254);
        data.push(value.len() as u8);
        data.push((value.len() >> 8) as u8);
        data.push((value.len() >> 16) as u8);
        prefix_length = 4;
    } else {
        return Err("TL byte string is too large".into());
    }
    data.extend_from_slice(value);
    let padding = (4 - ((prefix_length + value.len()) % 4)) % 4;
    data.resize(data.len() + padding, 0);
    Ok(())
}

fn append_tl_string(data: &mut Vec<u8>, value: &str) -> GeneratorResult<()> {
    append_tl_bytes(data, value.as_bytes())
}

struct TlReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TlReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn read_data(&mut self, length: usize) -> Option<&'a [u8]> {
        if length > self.remaining() {
            return None;
        }
        let start = self.offset;
        self.offset += length;
        Some(&self.data[start..self.offset])
    }

    fn read_i32(&mut self) -> Option<i32> {
        let bytes: [u8; 4] = self.read_data(4)?.try_into().ok()?;
        Some(i32::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> Option<i64> {
        let bytes: [u8; 8] = self.read_data(8)?.try_into().ok()?;
        Some(i64::from_le_bytes(bytes))
    }

    fn read_tl_bytes(&mut self) -> Option<&'a [u8]> {
        let first = *self.read_data(1)?.first()?;
        let (length, prefix_length) = if first < 254 {
            (first as usize, 1)
        } else if first == 254 {
            let length_bytes = self.read_data(3)?;
            (
                length_bytes[0] as usize
                    | ((length_bytes[1] as usize) << 8)
                    | ((length_bytes[2] as usize) << 16),
                4,
            )
        } else {
            return None;
        };
        let result = self.read_data(length)?;
        let padding = (4 - ((prefix_length + length) % 4)) % 4;
        self.read_data(padding)?;
        Some(result)
    }

    fn read_tl_string(&mut self) -> Option<String> {
        String::from_utf8(self.read_tl_bytes()?.to_vec()).ok()
    }
}

fn sha1_parts(first: &[u8], second: Option<&[u8]>) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(first);
    if let Some(second) = second {
        hasher.update(second);
    }
    hasher.finalize().to_vec()
}

fn sha256_parts(first: &[u8], second: Option<&[u8]>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(first);
    if let Some(second) = second {
        hasher.update(second);
    }
    hasher.finalize().to_vec()
}

fn random_data(length: usize) -> Vec<u8> {
    let mut data = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

fn aes_ige(input: &[u8], key: &[u8], iv: &[u8], encrypt: bool) -> GeneratorResult<Vec<u8>> {
    if input.len() & 15 != 0 || key.len() != 32 || iv.len() != 32 {
        return Err("Invalid AES-IGE input, key, or IV length".into());
    }
    let cipher = Aes256::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;
    let mut first_iv: [u8; 16] = iv[..16].try_into().unwrap();
    let mut second_iv: [u8; 16] = iv[16..].try_into().unwrap();
    let mut output = vec![0u8; input.len()];

    for (offset, source) in input.chunks_exact(16).enumerate() {
        let output_start = offset * 16;
        let source_block: [u8; 16] = source.try_into().unwrap();
        let mut temporary = [0u8; 16];
        if encrypt {
            for index in 0..16 {
                temporary[index] = source_block[index] ^ first_iv[index];
            }
            let mut block = Block::<Aes256>::clone_from_slice(&temporary);
            cipher.encrypt_block(&mut block);
            for index in 0..16 {
                output[output_start + index] = block[index] ^ second_iv[index];
            }
            first_iv.copy_from_slice(&output[output_start..output_start + 16]);
            second_iv = source_block;
        } else {
            for index in 0..16 {
                temporary[index] = source_block[index] ^ second_iv[index];
            }
            let mut block = Block::<Aes256>::clone_from_slice(&temporary);
            cipher.decrypt_block(&mut block);
            for index in 0..16 {
                output[output_start + index] = block[index] ^ first_iv[index];
            }
            first_iv = source_block;
            second_iv.copy_from_slice(&output[output_start..output_start + 16]);
        }
    }
    Ok(output)
}

struct AbridgedTransport {
    stream: TcpStream,
}

impl AbridgedTransport {
    fn connect(host: &str, port: u16) -> GeneratorResult<Self> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("Failed to resolve {host}:{port}: {error}"))?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, TIMEOUT) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(TIMEOUT))
                        .map_err(|error| error.to_string())?;
                    stream
                        .set_write_timeout(Some(TIMEOUT))
                        .map_err(|error| error.to_string())?;
                    return Ok(Self { stream });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(format!(
            "Failed to connect to Telegram DC {host}:{port}: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no resolved addresses".into())
        ))
    }

    fn initialize(&mut self) -> GeneratorResult<()> {
        self.stream
            .write_all(&[0xef])
            .map_err(|error| format!("Failed to initialize abridged transport: {error}"))
    }

    fn send_packet(&mut self, packet: &[u8]) -> GeneratorResult<()> {
        if packet.len() & 3 != 0 {
            return Err("MTProto packet length is not aligned".into());
        }
        let word_length = packet.len() / 4;
        if word_length < 127 {
            self.stream
                .write_all(&[word_length as u8])
                .map_err(|error| error.to_string())?;
        } else if word_length <= 0x00ff_ffff {
            let header = [
                0x7f,
                word_length as u8,
                (word_length >> 8) as u8,
                (word_length >> 16) as u8,
            ];
            self.stream
                .write_all(&header)
                .map_err(|error| error.to_string())?;
        } else {
            return Err("MTProto packet is too large".into());
        }
        self.stream
            .write_all(packet)
            .map_err(|error| format!("Failed to send MTProto packet: {error}"))
    }

    fn receive_packet(&mut self) -> GeneratorResult<Vec<u8>> {
        let mut first = [0u8; 1];
        self.stream
            .read_exact(&mut first)
            .map_err(|error| format!("Failed to receive MTProto packet header: {error}"))?;
        let word_length = if first[0] < 0x7f {
            first[0] as usize
        } else if first[0] == 0x7f {
            let mut extended = [0u8; 3];
            self.stream
                .read_exact(&mut extended)
                .map_err(|error| format!("Failed to receive MTProto extended header: {error}"))?;
            extended[0] as usize | ((extended[1] as usize) << 8) | ((extended[2] as usize) << 16)
        } else {
            return Err("Invalid abridged MTProto packet header".into());
        };
        if word_length == 0 || word_length > MAX_PACKET_WORDS {
            return Err("Invalid abridged MTProto packet length".into());
        }
        let mut packet = vec![0u8; word_length * 4];
        self.stream
            .read_exact(&mut packet)
            .map_err(|error| format!("Failed to receive MTProto packet body: {error}"))?;
        Ok(packet)
    }
}

fn message_id(time_offset: f64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        + time_offset;
    let seconds = now.floor() as u64;
    let fraction = ((now - seconds as f64) * (1u64 << 32) as f64) as u64;
    ((seconds << 32) | (fraction & !3)) as i64
}

fn send_plain_request(
    transport: &mut AbridgedTransport,
    body: &[u8],
    time_offset: f64,
    step: &str,
) -> GeneratorResult<Vec<u8>> {
    let mut message = Vec::new();
    append_i64(&mut message, 0);
    append_i64(&mut message, message_id(time_offset));
    append_i32(&mut message, body.len() as i32);
    message.extend_from_slice(body);
    transport.send_packet(&message)?;

    let packet = transport.receive_packet()?;
    let mut reader = TlReader::new(&packet);
    let auth_key_id = reader.read_i64();
    let _message_id = reader.read_i64();
    let length = reader.read_i32().unwrap_or(0);
    if auth_key_id != Some(0) || length <= 0 || length as usize > reader.remaining() {
        return Err(format!(
            "Invalid MTProto {step} response ({} bytes)",
            packet.len()
        ));
    }
    Ok(reader.read_data(length as usize).unwrap().to_vec())
}

fn big_endian_u64(data: &[u8]) -> Option<u64> {
    if data.len() > 8 {
        return None;
    }
    Some(
        data.iter()
            .fold(0u64, |result, byte| (result << 8) | (*byte as u64)),
    )
}

fn gcd(mut first: u64, mut second: u64) -> u64 {
    while second != 0 {
        let remainder = first % second;
        first = second;
        second = remainder;
    }
    first
}

fn multiply_modulo(first: u64, second: u64, modulus: u64) -> u64 {
    ((first as u128 * second as u128) % modulus as u128) as u64
}

fn factor_pq(value: u64) -> Option<u64> {
    if value & 1 == 0 {
        return Some(2);
    }
    if value < 4 {
        return None;
    }
    let mut rng = rand::thread_rng();
    for _ in 0..8 {
        let mut y = rng.gen_range(1..value);
        let c = rng.gen_range(1..value);
        let batch_size = 128u64;
        let mut factor = 1u64;
        let mut radius = 1u64;
        let mut product = 1u64;
        let mut x = 0u64;
        let mut saved_y = 0u64;
        while factor == 1 && radius < (1u64 << 32) {
            x = y;
            for _ in 0..radius {
                y = (multiply_modulo(y, y, value) + c) % value;
            }
            let mut offset = 0;
            while offset < radius && factor == 1 {
                saved_y = y;
                let count = batch_size.min(radius - offset);
                for _ in 0..count {
                    y = (multiply_modulo(y, y, value) + c) % value;
                    product = multiply_modulo(product, x.abs_diff(y), value);
                }
                factor = gcd(product, value);
                offset += batch_size;
            }
            radius <<= 1;
        }
        if factor == value {
            loop {
                saved_y = (multiply_modulo(saved_y, saved_y, value) + c) % value;
                factor = gcd(x.abs_diff(saved_y), value);
                if factor != 1 {
                    break;
                }
            }
        }
        if factor > 1 && factor < value {
            return Some(factor);
        }
    }
    None
}

fn big_endian_data_from_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first_nonzero..].to_vec()
}

fn der_length(data: &[u8], offset: &mut usize) -> GeneratorResult<usize> {
    let first = *data
        .get(*offset)
        .ok_or_else(|| "Truncated DER length".to_string())?;
    *offset += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || *offset + count > data.len() {
        return Err("Invalid DER length".into());
    }
    let mut length = 0usize;
    for byte in &data[*offset..*offset + count] {
        length = (length << 8) | *byte as usize;
    }
    *offset += count;
    Ok(length)
}

fn der_integer(data: &[u8], offset: &mut usize) -> GeneratorResult<Vec<u8>> {
    if data.get(*offset) != Some(&0x02) {
        return Err("Expected DER INTEGER".into());
    }
    *offset += 1;
    let length = der_length(data, offset)?;
    let value = data
        .get(*offset..*offset + length)
        .ok_or_else(|| "Truncated DER INTEGER".to_string())?;
    *offset += length;
    let value = if value.first() == Some(&0) {
        &value[1..]
    } else {
        value
    };
    Ok(value.to_vec())
}

fn rsa_components_from_der_base64(encoded: &str) -> GeneratorResult<(BigUint, BigUint)> {
    let der = BASE64
        .decode(encoded)
        .map_err(|error| format!("Invalid RSA key: {error}"))?;
    let mut offset = 0usize;
    if der.get(offset) != Some(&0x30) {
        return Err("Invalid RSA key sequence".into());
    }
    offset += 1;
    let sequence_length = der_length(&der, &mut offset)?;
    if offset + sequence_length != der.len() {
        return Err("Invalid RSA key length".into());
    }
    let modulus = BigUint::from_bytes_be(&der_integer(&der, &mut offset)?);
    let exponent = BigUint::from_bytes_be(&der_integer(&der, &mut offset)?);
    Ok((modulus, exponent))
}

fn telegram_rsa_components() -> GeneratorResult<(BigUint, BigUint)> {
    rsa_components_from_der_base64(TELEGRAM_RSA_KEY_DER_BASE64)
}

fn rsa_encrypt(inner_data: &[u8]) -> GeneratorResult<Vec<u8>> {
    let mut content = sha1_parts(inner_data, None);
    content.extend_from_slice(inner_data);
    if content.len() > 255 {
        return Err("p_q_inner_data is too large".into());
    }
    content.extend_from_slice(&random_data(255 - content.len()));
    let mut payload = vec![0u8; 1];
    payload.extend_from_slice(&content);

    let (modulus, exponent) = telegram_rsa_components()?;
    let encrypted = BigUint::from_bytes_be(&payload).modpow(&exponent, &modulus);
    let encrypted_bytes = encrypted.to_bytes_be();
    if encrypted_bytes.len() > 256 {
        return Err("Invalid RSA encrypted value".into());
    }
    let mut result = vec![0u8; 256 - encrypted_bytes.len()];
    result.extend_from_slice(&encrypted_bytes);
    Ok(result)
}

fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> GeneratorResult<Vec<u8>> {
    if input.len() & 15 != 0 || key.len() != 32 || iv.len() != 16 {
        return Err("Invalid AES-CBC input, key, or IV length".into());
    }
    let cipher = Aes256::new_from_slice(key).map_err(|_| "Invalid AES-256 key")?;
    let mut previous: [u8; 16] = iv.try_into().unwrap();
    let mut output = Vec::with_capacity(input.len());
    for source in input.chunks_exact(16) {
        let ciphertext: [u8; 16] = source.try_into().unwrap();
        let mut block = Block::<Aes256>::clone_from_slice(source);
        cipher.decrypt_block(&mut block);
        for index in 0..16 {
            block[index] ^= previous[index];
        }
        output.extend_from_slice(&block);
        previous = ciphertext;
    }
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupEndpoint {
    dc_id: i32,
    ip: String,
    port: u16,
    secret: Option<Vec<u8>>,
}


fn normalize_ipv6(ip: &str) -> String {
    // Telegram 配置里的 IPv6 可能存在 0000 展开形式，
    // 输出统一为 RFC 5952 风格，避免重复 endpoint。
    if let Ok(addr) = ip.parse::<Ipv6Addr>() {
        return addr.to_string();
    }
    ip.to_lowercase()
}

fn normalize_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(addr)) => addr.to_string(),
        Ok(IpAddr::V4(addr)) => addr.to_string(),
        Err(_) => normalize_ipv6(ip),
    }
}

fn ipv4_string(value: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff
    )
}

fn read_backup_endpoint(
    reader: &mut TlReader<'_>,
    dc_id: i32,
    constructor: Option<u32>,
) -> GeneratorResult<BackupEndpoint> {
    let constructor = constructor.unwrap_or(0xd433_ad73);
    if constructor != 0xd433_ad73 && constructor != 0x3798_2646 {
        return Err(format!(
            "Unsupported Telegram backup endpoint constructor 0x{constructor:08x}"
        ));
    }
    let ip = reader
        .read_i32()
        .ok_or_else(|| "Missing Telegram backup endpoint IP".to_string())? as u32;
    let port = reader
        .read_i32()
        .ok_or_else(|| "Missing Telegram backup endpoint port".to_string())?;
    if !(1..=5).contains(&dc_id) || !(1..=65535).contains(&port) {
        return Err("Invalid Telegram backup endpoint".into());
    }
    let secret = if constructor == 0x3798_2646 {
        Some(
            reader
                .read_tl_bytes()
                .ok_or_else(|| "Invalid Telegram backup endpoint secret".to_string())?
                .to_vec(),
        )
    } else {
        None
    };
    Ok(BackupEndpoint {
        dc_id,
        ip: ipv4_string(ip),
        port: port as u16,
        secret,
    })
}

fn parse_backup_config(data: &[u8]) -> GeneratorResult<Vec<BackupEndpoint>> {
    let mut reader = TlReader::new(data);
    let constructor = reader.read_i32().unwrap_or(0) as u32;
    let timestamp = reader
        .read_i32()
        .ok_or_else(|| "Missing Telegram backup timestamp".to_string())?;
    let expiration = reader
        .read_i32()
        .ok_or_else(|| "Missing Telegram backup expiration".to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64;
    if timestamp as i64 >= now + 20 * 60 || expiration as i64 <= now - 20 * 60 {
        return Err(format!(
            "Telegram backup configuration is outside its validity interval ({timestamp}...{expiration}, now {now})"
        ));
    }

    let mut endpoints = Vec::new();
    match constructor {
        0xd997_c3c5 => {
            let dc_id = reader
                .read_i32()
                .ok_or_else(|| "Missing Telegram backup DC ID".to_string())?;
            if reader.read_i32().unwrap_or(0) as u32 != 0x1cb5_c415 {
                return Err("Invalid Telegram backup endpoint vector".into());
            }
            let count = reader.read_i32().unwrap_or(0);
            if !(1..=1024).contains(&count) {
                return Err("Invalid Telegram backup endpoint count".into());
            }
            for _ in 0..count {
                endpoints.push(read_backup_endpoint(&mut reader, dc_id, None)?);
            }
        }
        0x5a59_2a6c => {
            let rule_count = reader.read_i32().unwrap_or(0);
            if !(1..=1024).contains(&rule_count) {
                return Err("Invalid Telegram backup rule count".into());
            }
            for _ in 0..rule_count {
                if reader.read_i32().unwrap_or(0) as u32 != 0x4679_b65f {
                    return Err("Invalid Telegram backup rule".into());
                }
                // The generator intentionally unions all phone-prefix variants.
                // A published fallback file must work before an account phone
                // number is available and should not lose region-specific seeds.
                reader
                    .read_tl_string()
                    .ok_or_else(|| "Invalid Telegram backup phone rules".to_string())?;
                let dc_id = reader
                    .read_i32()
                    .ok_or_else(|| "Missing Telegram backup rule DC ID".to_string())?;
                let endpoint_count = reader.read_i32().unwrap_or(0);
                if !(1..=1024).contains(&endpoint_count) {
                    return Err("Invalid Telegram backup rule endpoint count".into());
                }
                for _ in 0..endpoint_count {
                    let endpoint_constructor = reader
                        .read_i32()
                        .ok_or_else(|| "Missing Telegram backup endpoint constructor".to_string())?
                        as u32;
                    endpoints.push(read_backup_endpoint(
                        &mut reader,
                        dc_id,
                        Some(endpoint_constructor),
                    )?);
                }
            }
        }
        _ => {
            return Err(format!(
                "Unsupported Telegram backup configuration constructor 0x{constructor:08x}"
            ));
        }
    }
    Ok(endpoints)
}

fn decode_backup_config(blob: &[u8]) -> GeneratorResult<Vec<BackupEndpoint>> {
    if blob.len() < 256 {
        return Err("Telegram backup configuration is shorter than 256 bytes".into());
    }
    let (modulus, exponent) = rsa_components_from_der_base64(BACKUP_CONFIG_RSA_KEY_DER_BASE64)?;
    let transformed = BigUint::from_bytes_be(&blob[..256]).modpow(&exponent, &modulus);
    let transformed_bytes = transformed.to_bytes_be();
    if transformed_bytes.len() > 256 {
        return Err("Invalid Telegram backup RSA result".into());
    }
    let mut block = vec![0u8; 256 - transformed_bytes.len()];
    block.extend_from_slice(&transformed_bytes);

    let decrypted = aes_cbc_decrypt(&block[32..], &block[..32], &block[16..32])?;
    if decrypted.len() != 224 {
        return Err("Invalid Telegram backup decrypted length".into());
    }
    let expected_hash = Sha256::digest(&decrypted[..208]);
    if expected_hash[..16] != decrypted[208..224] {
        return Err("Telegram backup signature hash mismatch".into());
    }
    let data_length = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
    if data_length == 0 || data_length > 204 || data_length & 3 != 0 {
        return Err("Invalid Telegram backup TL data length".into());
    }
    parse_backup_config(&decrypted[4..4 + data_length])
}

fn fetch_backup_endpoints() -> GeneratorResult<Vec<BackupEndpoint>> {
    let response: Value = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| format!("Failed to build backup HTTP client: {error}"))?
        .get(BACKUP_CONFIG_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("Failed to fetch Telegram backup configuration: {error}"))?
        .json()
        .map_err(|error| format!("Invalid Telegram backup DNS response: {error}"))?;
    let answers = response["Answer"]
        .as_array()
        .ok_or_else(|| "Telegram backup DNS response has no TXT answers".to_string())?;
    let mut parts: Vec<String> = answers
        .iter()
        .filter_map(|answer| answer["data"].as_str())
        .map(|part| {
            part.chars()
                .filter(|character| {
                    character.is_ascii_alphanumeric() || *character == '+' || *character == '/'
                })
                .collect()
        })
        .collect();
    if parts.is_empty() {
        return Err("Telegram backup DNS response has no usable TXT data".into());
    }
    parts.sort_by_key(|part| std::cmp::Reverse(part.len()));
    let mut encoded = parts.concat();
    while encoded.len() & 3 != 0 {
        encoded.push('=');
    }
    let blob = BASE64
        .decode(encoded)
        .map_err(|error| format!("Invalid Telegram backup base64 data: {error}"))?;
    decode_backup_config(&blob)
}

fn option_i32(option: &Value, key: &str) -> Option<i32> {
    option[key].as_i64()?.try_into().ok()
}

fn endpoint_flags(ip: &str, has_secret: bool) -> i32 {
    let mut flags = DC_OPTION_FLAG_STATIC;
    if ip.contains(':') {
        flags |= DC_OPTION_FLAG_IPV6;
    }
    if has_secret {
        flags |= DC_OPTION_FLAG_SECRET;
    }
    flags
}

fn merge_endpoint(
    config: &mut Value,
    dc_id: i32,
    ip: &str,
    port: u16,
    secret: Option<&[u8]>,
) -> GeneratorResult<bool> {
    let ip = normalize_ip(ip);
    let options = config["options"]
        .as_array_mut()
        .ok_or_else(|| "Generated config has no DC options array".to_string())?;
    let encoded_secret = secret.map(|value| BASE64.encode(value));
    let functional_flags =
        DC_OPTION_FLAG_MEDIA_ONLY | DC_OPTION_FLAG_TCPO_ONLY | DC_OPTION_FLAG_CDN;
    let mut matched = false;

    for option in options.iter_mut() {
        if option_i32(option, "id") != Some(dc_id)
            || option["ip"].as_str() != Some(&ip)
            || option_i32(option, "port") != Some(port as i32)
        {
            continue;
        }
        let existing_flags = option_i32(option, "flags").unwrap_or(0);
        if existing_flags & functional_flags != 0 {
            continue;
        }
        let existing_secret = option["secret"].as_str();
        if existing_secret != encoded_secret.as_deref() {
            continue;
        }
        option["flags"] =
            Value::from(existing_flags | endpoint_flags(&ip, encoded_secret.is_some()));
        matched = true;
    }

    if !matched {
        let mut option = json!({
            "id": dc_id,
            "ip": ip,
            "port": port,
            "flags": endpoint_flags(&ip, encoded_secret.is_some()),
        });
        if let Some(secret) = encoded_secret {
            option["secret"] = Value::String(secret);
        }
        options.push(option);
    }
    Ok(!matched)
}

fn deduplicate_options(config: &mut Value) -> GeneratorResult<usize> {
    let options = config["options"]
        .as_array_mut()
        .ok_or_else(|| "Generated config has no DC options array".to_string())?;
    let previous_count = options.len();
    let mut seen = HashSet::new();
    options.retain(|option| {
        let key = (
            option_i32(option, "id"),
            option["ip"].as_str().map(str::to_owned),
            option_i32(option, "port"),
            option_i32(option, "flags"),
            option["secret"].as_str().map(str::to_owned),
        );
        seen.insert(key)
    });
    Ok(previous_count - options.len())
}

fn merge_fallback_endpoints(
    config: &mut Value,
    backup_endpoints: &[BackupEndpoint],
) -> GeneratorResult<(usize, usize, usize)> {
    let mut backup_added = 0;
    for endpoint in backup_endpoints {
        if merge_endpoint(
            config,
            endpoint.dc_id,
            &endpoint.ip,
            endpoint.port,
            endpoint.secret.as_deref(),
        )? {
            backup_added += 1;
        }
    }

    let mut bootstrap_added = 0;
    for &(dc_id, ip, port) in BOOTSTRAP_ENDPOINTS {
        if merge_endpoint(config, dc_id, ip, port, None)? {
            bootstrap_added += 1;
        }
    }
    let duplicates_removed = deduplicate_options(config)?;
    Ok((backup_added, bootstrap_added, duplicates_removed))
}

fn temporary_aes(server_nonce: &[u8], new_nonce: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hash1 = sha1_parts(new_nonce, Some(server_nonce));
    let hash2 = sha1_parts(server_nonce, Some(new_nonce));
    let hash3 = sha1_parts(new_nonce, Some(new_nonce));
    let mut key = hash1;
    key.extend_from_slice(&hash2[..12]);
    let mut iv = hash2[12..20].to_vec();
    iv.extend_from_slice(&hash3);
    iv.extend_from_slice(&new_nonce[..4]);
    (key, iv)
}

fn padded_ige_plaintext(inner_data: &[u8]) -> Vec<u8> {
    let mut result = sha1_parts(inner_data, None);
    result.extend_from_slice(inner_data);
    let padding = (16 - (result.len() % 16)) % 16;
    result.extend_from_slice(&random_data(padding));
    result
}

fn biguint_data(number: &BigUint, padded_length: Option<usize>) -> GeneratorResult<Vec<u8>> {
    let bytes = number.to_bytes_be();
    if let Some(length) = padded_length {
        if bytes.len() > length {
            return Err("Big integer does not fit padded length".into());
        }
        let mut result = vec![0u8; length - bytes.len()];
        result.extend_from_slice(&bytes);
        Ok(result)
    } else {
        Ok(bytes)
    }
}

struct Authentication {
    auth_key: Vec<u8>,
    auth_key_id: Vec<u8>,
    server_salt: i64,
    time_offset: f64,
}

fn perform_authentication(transport: &mut AbridgedTransport) -> GeneratorResult<Authentication> {
    let nonce = random_data(16);
    let mut request_pq = Vec::new();
    append_i32(&mut request_pq, 0xbe7e8ef1u32 as i32);
    request_pq.extend_from_slice(&nonce);
    let response_pq = send_plain_request(transport, &request_pq, 0.0, "req_pq")?;
    let mut reader = TlReader::new(&response_pq);
    let constructor = reader.read_i32().unwrap_or(0) as u32;
    let returned_nonce = reader.read_data(16).unwrap_or_default();
    let server_nonce = reader.read_data(16).unwrap_or_default().to_vec();
    let pq_data = reader.read_tl_bytes().unwrap_or_default().to_vec();
    let vector_constructor = reader.read_i32().unwrap_or(0) as u32;
    let fingerprint_count = reader.read_i32().unwrap_or(0);
    if constructor != 0x05162463
        || returned_nonce != nonce
        || server_nonce.len() != 16
        || pq_data.is_empty()
        || vector_constructor != 0x1cb5c415
        || !(1..=64).contains(&fingerprint_count)
    {
        return Err("Invalid resPQ response".into());
    }
    let mut has_key = false;
    for _ in 0..fingerprint_count {
        let fingerprint = reader
            .read_i64()
            .ok_or_else(|| "Invalid resPQ fingerprint list".to_string())?;
        if fingerprint == RSA_FINGERPRINT {
            has_key = true;
        }
    }

    let pq = big_endian_u64(&pq_data).ok_or_else(|| "Invalid MTProto pq".to_string())?;
    let mut p = factor_pq(pq).ok_or_else(|| "Failed to factor MTProto pq".to_string())?;
    if !has_key {
        return Err("Telegram did not offer the built-in RSA key".into());
    }
    if pq == 0 || pq % p != 0 {
        return Err("Invalid MTProto pq factors".into());
    }
    let mut q = pq / p;
    if p > q {
        std::mem::swap(&mut p, &mut q);
    }
    let p_data = big_endian_data_from_u64(p);
    let q_data = big_endian_data_from_u64(q);
    let new_nonce = random_data(32);

    let mut inner_pq = Vec::new();
    append_i32(&mut inner_pq, 0x83c95aecu32 as i32);
    append_tl_bytes(&mut inner_pq, &pq_data)?;
    append_tl_bytes(&mut inner_pq, &p_data)?;
    append_tl_bytes(&mut inner_pq, &q_data)?;
    inner_pq.extend_from_slice(&nonce);
    inner_pq.extend_from_slice(&server_nonce);
    inner_pq.extend_from_slice(&new_nonce);
    let rsa_encrypted = rsa_encrypt(&inner_pq)?;

    let mut dh_request = Vec::new();
    append_i32(&mut dh_request, 0xd712e4beu32 as i32);
    dh_request.extend_from_slice(&nonce);
    dh_request.extend_from_slice(&server_nonce);
    append_tl_bytes(&mut dh_request, &p_data)?;
    append_tl_bytes(&mut dh_request, &q_data)?;
    append_i64(&mut dh_request, RSA_FINGERPRINT);
    append_tl_bytes(&mut dh_request, &rsa_encrypted)?;
    let dh_response = send_plain_request(transport, &dh_request, 0.0, "req_DH_params")?;
    let mut dh_reader = TlReader::new(&dh_response);
    if dh_reader.read_i32().unwrap_or(0) as u32 != 0xd0e8075c
        || dh_reader.read_data(16).unwrap_or_default() != nonce
        || dh_reader.read_data(16).unwrap_or_default() != server_nonce
    {
        return Err("Invalid server_DH_params response".into());
    }
    let encrypted_answer = dh_reader
        .read_tl_bytes()
        .ok_or_else(|| "Missing encrypted server_DH_inner_data".to_string())?;

    let (temporary_key, temporary_iv) = temporary_aes(&server_nonce, &new_nonce);
    let answer = aes_ige(encrypted_answer, &temporary_key, &temporary_iv, false)?;
    let mut answer_reader = TlReader::new(&answer);
    let answer_hash = answer_reader
        .read_data(20)
        .ok_or_else(|| "Invalid server_DH_inner_data hash".to_string())?
        .to_vec();
    let inner_start = answer_reader.offset;
    let constructor = answer_reader.read_i32().unwrap_or(0) as u32;
    let returned_nonce = answer_reader.read_data(16).unwrap_or_default();
    let returned_server_nonce = answer_reader.read_data(16).unwrap_or_default();
    let generator = answer_reader.read_i32().unwrap_or(0);
    let dh_prime_data = answer_reader.read_tl_bytes().unwrap_or_default().to_vec();
    let g_a_data = answer_reader.read_tl_bytes().unwrap_or_default().to_vec();
    let server_time = answer_reader.read_i32().unwrap_or(0);
    if constructor != 0xb5890dba
        || returned_nonce != nonce
        || returned_server_nonce != server_nonce
        || generator <= 0
        || dh_prime_data.is_empty()
        || g_a_data.is_empty()
        || server_time <= 0
    {
        return Err("Invalid server_DH_inner_data".into());
    }
    if answer_hash != sha1_parts(&answer[inner_start..answer_reader.offset], None) {
        return Err("Invalid server_DH_inner_data hash".into());
    }

    let dh_prime = BigUint::from_bytes_be(&dh_prime_data);
    let g_a = BigUint::from_bytes_be(&g_a_data);
    let one = BigUint::one();
    if dh_prime.is_zero() || g_a <= one || g_a >= (&dh_prime - &one) {
        return Err("Invalid server DH values".into());
    }
    let g = BigUint::from(generator as u32);
    let b = BigUint::from_bytes_be(&random_data(256));
    let g_b = g.modpow(&b, &dh_prime);
    let auth_key_number = g_a.modpow(&b, &dh_prime);
    let g_b_data = biguint_data(&g_b, None)?;
    let auth_key = biguint_data(&auth_key_number, Some(256))?;

    let mut client_inner = Vec::new();
    append_i32(&mut client_inner, 0x6643b654u32 as i32);
    client_inner.extend_from_slice(&nonce);
    client_inner.extend_from_slice(&server_nonce);
    append_i64(&mut client_inner, 0);
    append_tl_bytes(&mut client_inner, &g_b_data)?;
    let encrypted_client_inner = aes_ige(
        &padded_ige_plaintext(&client_inner),
        &temporary_key,
        &temporary_iv,
        true,
    )?;
    let mut set_client_dh = Vec::new();
    append_i32(&mut set_client_dh, 0xf5045f1fu32 as i32);
    set_client_dh.extend_from_slice(&nonce);
    set_client_dh.extend_from_slice(&server_nonce);
    append_tl_bytes(&mut set_client_dh, &encrypted_client_inner)?;
    let time_offset = server_time as f64
        - SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
    let set_response = send_plain_request(
        transport,
        &set_client_dh,
        time_offset,
        "set_client_DH_params",
    )?;
    let mut set_reader = TlReader::new(&set_response);
    if set_reader.read_i32().unwrap_or(0) as u32 != 0x3bcbf734
        || set_reader.read_data(16).unwrap_or_default() != nonce
        || set_reader.read_data(16).unwrap_or_default() != server_nonce
    {
        return Err("Invalid dh_gen_ok response".into());
    }
    let new_nonce_hash = set_reader
        .read_data(16)
        .ok_or_else(|| "Missing dh_gen_ok nonce hash".to_string())?;
    let auth_key_hash = sha1_parts(&auth_key, None);
    let mut hash_input = new_nonce.clone();
    hash_input.push(1);
    hash_input.extend_from_slice(&auth_key_hash[..8]);
    let expected_hash = sha1_parts(&hash_input, None)[4..20].to_vec();
    if new_nonce_hash != expected_hash {
        return Err("Invalid dh_gen_ok nonce hash".into());
    }

    let mut salt_bytes = [0u8; 8];
    for index in 0..8 {
        salt_bytes[index] = new_nonce[index] ^ server_nonce[index];
    }
    Ok(Authentication {
        auth_key,
        auth_key_id: auth_key_hash[auth_key_hash.len() - 8..].to_vec(),
        server_salt: i64::from_le_bytes(salt_bytes),
        time_offset,
    })
}

fn message_aes(auth_key: &[u8], message_key: &[u8], client: bool) -> (Vec<u8>, Vec<u8>) {
    let x = if client { 0 } else { 8 };
    let mut a_input = message_key.to_vec();
    a_input.extend_from_slice(&auth_key[x..x + 36]);
    let mut b_input = auth_key[x + 40..x + 76].to_vec();
    b_input.extend_from_slice(message_key);
    let a = sha256_parts(&a_input, None);
    let b = sha256_parts(&b_input, None);
    let mut key = a[..8].to_vec();
    key.extend_from_slice(&b[8..24]);
    key.extend_from_slice(&a[24..32]);
    let mut iv = b[..8].to_vec();
    iv.extend_from_slice(&a[8..24]);
    iv.extend_from_slice(&b[24..32]);
    (key, iv)
}

fn help_get_config_body() -> GeneratorResult<Vec<u8>> {
    let mut body = Vec::new();
    append_i32(&mut body, 0xda9b0d0du32 as i32);
    append_i32(&mut body, API_LAYER);
    append_i32(&mut body, 0xc1cd5ea9u32 as i32);
    append_i32(&mut body, 0);
    append_i32(&mut body, API_ID);
    append_tl_string(&mut body, "Surge")?;
    append_tl_string(&mut body, env::consts::OS)?;
    append_tl_string(&mut body, "1.0")?;
    append_tl_string(&mut body, "en")?;
    append_tl_string(&mut body, "")?;
    append_tl_string(&mut body, "en")?;
    append_i32(&mut body, 0xc4f9186bu32 as i32);
    Ok(body)
}

fn gzip_decompress(compressed: &[u8]) -> GeneratorResult<Vec<u8>> {
    let decoder = GzDecoder::new(compressed);
    let mut result = Vec::new();
    decoder
        .take(1024 * 1024 + 1)
        .read_to_end(&mut result)
        .map_err(|error| format!("Failed to decompress gzip_packed response: {error}"))?;
    if result.len() > 1024 * 1024 {
        return Err("Decompressed MTProto response is too large".into());
    }
    Ok(result)
}

fn parse_config(body: &[u8]) -> GeneratorResult<Value> {
    let mut reader = TlReader::new(body);
    let constructor = reader.read_i32().unwrap_or(0) as u32;
    let _flags = reader
        .read_i32()
        .ok_or_else(|| "Missing config flags".to_string())?;
    let date = reader
        .read_i32()
        .ok_or_else(|| "Missing config date".to_string())?;
    let expires = reader
        .read_i32()
        .ok_or_else(|| "Missing config expiration".to_string())?;
    let bool_constructor = reader.read_i32().unwrap_or(0) as u32;
    let this_dc = reader
        .read_i32()
        .ok_or_else(|| "Missing this_dc".to_string())?;
    let vector_constructor = reader.read_i32().unwrap_or(0) as u32;
    let count = reader.read_i32().unwrap_or(0);
    if constructor != 0xcc1a241e
        || (bool_constructor != 0x997275b5 && bool_constructor != 0xbc799737)
        || vector_constructor != 0x1cb5c415
        || !(1..=1024).contains(&count)
    {
        return Err("Invalid help.config response".into());
    }

    let mut options = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let constructor = reader.read_i32().unwrap_or(0) as u32;
        let flags = reader
            .read_i32()
            .ok_or_else(|| "Missing DC option flags".to_string())?;
        let dc_id = reader
            .read_i32()
            .ok_or_else(|| "Missing DC ID".to_string())?;
        let ip = reader
            .read_tl_string()
            .ok_or_else(|| "Invalid DC IP address".to_string())?;
        let port = reader
            .read_i32()
            .ok_or_else(|| "Missing DC port".to_string())?;
        if constructor != 0x18b7a10d || dc_id <= 0 || ip.is_empty() || !(1..=65535).contains(&port)
        {
            return Err("Invalid DC option".into());
        }
        let mut option = json!({
            "id": dc_id,
            "ip": ip,
            "port": port,
            "flags": flags,
        });
        if flags & (1 << 10) != 0 {
            let secret = reader
                .read_tl_bytes()
                .ok_or_else(|| "Invalid DC option secret".to_string())?;
            option["secret"] = Value::String(BASE64.encode(secret));
        }
        options.push(option);
    }
    Ok(json!({
        "version": 1,
        "date": date,
        "expires": expires,
        "this_dc": this_dc,
        "options": options,
    }))
}

fn find_config_in_body(
    body: &[u8],
    request_message_id: i64,
    depth: usize,
) -> GeneratorResult<Option<Value>> {
    if depth > 4 || body.len() < 4 {
        return Ok(None);
    }
    let mut reader = TlReader::new(body);
    let constructor = reader.read_i32().unwrap_or(0) as u32;
    match constructor {
        0xcc1a241e => parse_config(body).map(Some),
        0xf35c6d01 => {
            let response_to = reader.read_i64().unwrap_or(0);
            if response_to != request_message_id {
                return Ok(None);
            }
            let result = reader.read_data(reader.remaining()).unwrap_or_default();
            let mut result_reader = TlReader::new(result);
            if result_reader.read_i32().unwrap_or(0) as u32 == 0x2144ca19 {
                let error_code = result_reader.read_i32().unwrap_or(0);
                let message = result_reader
                    .read_tl_string()
                    .unwrap_or_else(|| "Unknown RPC error".into());
                return Err(format!("Telegram RPC error {error_code}: {message}"));
            }
            find_config_in_body(result, request_message_id, depth + 1)
        }
        0x73f1f8dc => {
            let count = reader.read_i32().unwrap_or(0);
            if !(1..=1024).contains(&count) {
                return Ok(None);
            }
            for _ in 0..count {
                let _message_id = reader.read_i64();
                let _sequence = reader.read_i32();
                let length = reader.read_i32().unwrap_or(0);
                if length <= 0 || length as usize > reader.remaining() {
                    return Ok(None);
                }
                let nested = reader.read_data(length as usize).unwrap();
                if let Some(config) = find_config_in_body(nested, request_message_id, depth + 1)? {
                    return Ok(Some(config));
                }
            }
            Ok(None)
        }
        0x3072cfa1 => {
            let packed = reader
                .read_tl_bytes()
                .ok_or_else(|| "Invalid gzip_packed response".to_string())?;
            let unpacked = gzip_decompress(packed)?;
            find_config_in_body(&unpacked, request_message_id, depth + 1)
        }
        _ => Ok(None),
    }
}

fn fetch_config(host: &str, port: u16) -> GeneratorResult<Value> {
    let mut transport = AbridgedTransport::connect(host, port)?;
    transport.initialize()?;
    let authentication = perform_authentication(&mut transport)?;

    let request_body = help_get_config_body()?;
    let request_message_id = message_id(authentication.time_offset);
    let session_id = rand::thread_rng().next_u64() as i64;
    let mut plaintext = Vec::new();
    append_i64(&mut plaintext, authentication.server_salt);
    append_i64(&mut plaintext, session_id);
    append_i64(&mut plaintext, request_message_id);
    append_i32(&mut plaintext, 1);
    append_i32(&mut plaintext, request_body.len() as i32);
    plaintext.extend_from_slice(&request_body);
    let padding_length = 12 + ((16 - ((plaintext.len() + 12) % 16)) % 16);
    plaintext.extend_from_slice(&random_data(padding_length));

    let mut message_key_input = authentication.auth_key[88..120].to_vec();
    message_key_input.extend_from_slice(&plaintext);
    let message_key = sha256_parts(&message_key_input, None)[8..24].to_vec();
    let (aes_key, aes_iv) = message_aes(&authentication.auth_key, &message_key, true);
    let encrypted = aes_ige(&plaintext, &aes_key, &aes_iv, true)?;
    let mut packet = authentication.auth_key_id.clone();
    packet.extend_from_slice(&message_key);
    packet.extend_from_slice(&encrypted);
    transport.send_packet(&packet)?;

    for _ in 0..8 {
        let response_packet = transport.receive_packet()?;
        if response_packet.len() < 24
            || response_packet.len() % 16 != 8
            || response_packet[..8] != authentication.auth_key_id
        {
            return Err("Invalid encrypted MTProto config response".into());
        }
        let response_message_key = &response_packet[8..24];
        let (aes_key, aes_iv) = message_aes(&authentication.auth_key, response_message_key, false);
        let response_plaintext = aes_ige(&response_packet[24..], &aes_key, &aes_iv, false)?;
        let mut hash_input = authentication.auth_key[96..128].to_vec();
        hash_input.extend_from_slice(&response_plaintext);
        let expected_message_key = sha256_parts(&hash_input, None)[8..24].to_vec();
        if response_message_key != expected_message_key {
            return Err("Invalid encrypted MTProto message key".into());
        }
        let mut reader = TlReader::new(&response_plaintext);
        let _remote_salt = reader.read_i64();
        let returned_session_id = reader.read_i64();
        let _remote_message_id = reader.read_i64();
        let _sequence = reader.read_i32();
        let length = reader.read_i32().unwrap_or(0);
        if returned_session_id != Some(session_id)
            || length <= 0
            || length as usize > reader.remaining()
        {
            return Err("Invalid encrypted MTProto message envelope".into());
        }
        let body = reader.read_data(length as usize).unwrap();
        if let Some(config) = find_config_in_body(body, request_message_id, 0)? {
            return Ok(config);
        }
    }
    Err("No valid help.getConfig response was received".into())
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} [output.json|-] [host] [port]");
}

fn compact_ipv6_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "ip" {
                    if let Some(ip) = item.as_str() {
                        *item = Value::String(normalize_ip(ip));
                    }
                } else {
                    compact_ipv6_json(item);
                }
            }
        }
        Value::Array(array) => {
            for item in array.iter_mut() {
                compact_ipv6_json(item);
            }
        }
        _ => {}
    }
}

fn write_output(path: &str, config: &Value) -> GeneratorResult<()> {
    let mut config = config.clone();
    // 输出前统一压缩 IPv6，例如：
    // 2001:0b28:f23d:f001:0000:0000:0000:000a
    // -> 2001:b28:f23d:f001::a
    compact_ipv6_json(&mut config);

    let mut output = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Failed to format generated JSON: {error}"))?;
    output.push('\n');
    if path == "-" {
        print!("{output}");
        return Ok(());
    }
    fs::write(Path::new(path), output.as_bytes())
        .map_err(|error| format!("Failed to write {path}: {error}"))?;
    eprintln!("Wrote {} bytes to {path}", output.len());
    Ok(())
}

fn run() -> GeneratorResult<()> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() > 4 {
        print_usage(&arguments[0]);
        return Err("Too many arguments".into());
    }
    let output_path = arguments
        .get(1)
        .map(String::as_str)
        .unwrap_or("mtproto-dc-config.json");
    let explicit_endpoint = if let Some(host) = arguments.get(2) {
        let port = arguments
            .get(3)
            .map(|value| value.parse::<u16>())
            .transpose()
            .map_err(|_| "Invalid port".to_string())?
            .unwrap_or(443);
        Some((host.as_str(), port))
    } else {
        None
    };

    let endpoints: Vec<(&str, u16)> = if let Some(endpoint) = explicit_endpoint {
        vec![endpoint]
    } else {
        BOOTSTRAP_ENDPOINTS
            .iter()
            .map(|&(_, host, port)| (host, port))
            .collect()
    };
    let mut last_error = None;
    let mut config = None;
    for (host, port) in endpoints {
        eprintln!("Fetching help.getConfig from {host}:{port}...");
        match fetch_config(host, port) {
            Ok(value) => {
                config = Some(value);
                break;
            }
            Err(error) => {
                eprintln!("  failed: {error}");
                last_error = Some(error);
            }
        }
    }
    let mut config = config.ok_or_else(|| {
        format!(
            "All bootstrap endpoints failed: {}",
            last_error.unwrap_or_else(|| "no endpoints".into())
        )
    })?;

    let backup_endpoints = match fetch_backup_endpoints() {
        Ok(endpoints) => {
            eprintln!(
                "Decoded {} endpoints from Telegram backup configuration.",
                endpoints.len()
            );
            endpoints
        }
        Err(error) => {
            eprintln!(
                "Warning: {error}; continuing with help.getConfig and built-in bootstrap endpoints."
            );
            Vec::new()
        }
    };
    let (backup_added, bootstrap_added, duplicates_removed) =
        merge_fallback_endpoints(&mut config, &backup_endpoints)?;
    eprintln!(
        "Merged {backup_added} backup and {bootstrap_added} bootstrap endpoints; removed {duplicates_removed} duplicates."
    );
    write_output(output_path, &config)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_static_fallbacks_and_deduplicates_existing_options() {
        let mut config = json!({
            "options": [
                {
                    "id": 5,
                    "ip": "91.108.56.191",
                    "port": 443,
                    "flags": 0
                },
                {
                    "id": 5,
                    "ip": "91.108.56.191",
                    "port": 443,
                    "flags": DC_OPTION_FLAG_STATIC
                }
            ]
        });
        let backup = vec![
            BackupEndpoint {
                dc_id: 5,
                ip: "91.108.56.201".into(),
                port: 443,
                secret: None,
            },
            BackupEndpoint {
                dc_id: 5,
                ip: "91.108.56.191".into(),
                port: 443,
                secret: None,
            },
        ];

        let (backup_added, _, duplicates_removed) =
            merge_fallback_endpoints(&mut config, &backup).unwrap();
        let options = config["options"].as_array().unwrap();

        assert_eq!(backup_added, 1);
        assert_eq!(duplicates_removed, 1);
        assert_eq!(
            options
                .iter()
                .filter(|option| option["ip"] == "91.108.56.191")
                .count(),
            1
        );
        assert!(options.iter().any(|option| {
            option["id"] == 5
                && option["ip"] == "91.108.56.201"
                && option["flags"] == DC_OPTION_FLAG_STATIC
        }));
        assert!(options.iter().any(|option| {
            option["id"] == 5
                && option["ip"] == "2001:b28:f23f:f005::a"
                && option["flags"] == DC_OPTION_FLAG_STATIC | DC_OPTION_FLAG_IPV6
        }));
    }

    #[test]
    fn parses_legacy_backup_endpoint_list() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let mut data = Vec::new();
        append_i32(&mut data, 0xd997_c3c5u32 as i32);
        append_i32(&mut data, now - 60);
        append_i32(&mut data, now + 3600);
        append_i32(&mut data, 5);
        append_i32(&mut data, 0x1cb5_c415);
        append_i32(&mut data, 1);
        append_i32(&mut data, u32::from_be_bytes([91, 108, 56, 201]) as i32);
        append_i32(&mut data, 443);

        assert_eq!(
            parse_backup_config(&data).unwrap(),
            vec![BackupEndpoint {
                dc_id: 5,
                ip: "91.108.56.201".into(),
                port: 443,
                secret: None,
            }]
        );
    }
}
