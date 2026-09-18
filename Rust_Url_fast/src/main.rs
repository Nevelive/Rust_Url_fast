use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use hmac::{Hmac, Mac};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Method, Request};
use http_body_util::BodyExt;
use http_body_util::Empty;
use httpdate::fmt_http_date;
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use k256::elliptic_curve::rand_core::OsRng;
use k256::SecretKey;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use sha3::{Digest, Keccak256};
use tokio::time::{Duration, sleep};
use url::Url;
use uuid::Uuid;

const POLYGON_USDC_ASSET_ID: &str = "c966_t0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const DEFAULT_AMOUNT: &str = "500";
const DEFAULT_CURRENCY: &str = "CAD";
const TARGET_PROVIDER: &str = "Mercuryo";
const GATEWAY_BASE_URL: &str = "https://tws.trustwallet.com";

type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Debug, Deserialize)]
struct OnrampQuote {
    #[serde(rename = "quoteId")]
    quote_id: String,
    provider: String,
}

#[derive(Debug, Deserialize)]
struct BuyResponse {
    url: String,
}

#[derive(Debug, Deserialize)]
struct GatewayQuoteResponse {
    quotes: Vec<GatewayQuote>,
}

#[derive(Debug, Deserialize)]
struct GatewayQuote {
    id: String,
    provider: GatewayProvider,
}

#[derive(Debug, Deserialize)]
struct GatewayProvider {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GatewayBuyResponse {
    url: Option<String>,
    redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StoredCredentials {
    #[serde(rename = "accessId")]
    access_id: String,
    #[serde(rename = "hmacSecret")]
    hmac_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let credentials = load_credentials().context("missing Trust Wallet credentials")?;

    let amount = env::var("TWAK_FIAT_AMOUNT").unwrap_or_else(|_| DEFAULT_AMOUNT.to_string());
    let currency = env::var("TWAK_FIAT_CURRENCY").unwrap_or_else(|_| DEFAULT_CURRENCY.to_string());
    let asset = env::var("TWAK_ASSET_ID").unwrap_or_else(|_| POLYGON_USDC_ASSET_ID.to_string());
    let provider = env::var("TWAK_PROVIDER").unwrap_or_else(|_| TARGET_PROVIDER.to_string());
    let polygon_address = generate_polygon_address();
    let client = GatewayClient::new(credentials);
    let quotes = client
        .onramp_quote(&amount, &currency, &asset, &polygon_address)
        .await?;
    let mercuryo_quote = quotes
        .into_iter()
        .find(|quote| quote.provider.eq_ignore_ascii_case(&provider))
        .ok_or_else(|| anyhow!("no {provider} quote returned for {amount} {currency}"))?;
    let buy = client.onramp_buy(&mercuryo_quote.quote_id, &polygon_address).await?;
    let final_url = ensure_address_query(&buy.url, &polygon_address)?;

    println!("{final_url}");

    Ok(())
}

fn read_required_env(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("environment variable {name} is not set"))?;
    if value.trim().is_empty() {
        bail!("environment variable {name} is empty");
    }
    Ok(value)
}

fn load_credentials() -> Result<StoredCredentials> {
    let access_id = read_required_env("TWAK_ACCESS_ID")
        .or_else(|_| read_required_env("TW_ACCESS_ID"));
    let hmac_secret = read_required_env("TWAK_HMAC_SECRET")
        .or_else(|_| read_required_env("TW_HMAC_SECRET"));

    match (access_id, hmac_secret) {
        (Ok(access_id), Ok(hmac_secret)) => {
            return Ok(StoredCredentials {
                access_id,
                hmac_secret,
            });
        }
        _ => {}
    }

    let credentials_path = default_credentials_path()?;
    let raw = fs::read_to_string(&credentials_path).with_context(|| {
        format!(
            "failed to read existing twak credentials from {}",
            credentials_path.display()
        )
    })?;
    let parsed: StoredCredentials =
        serde_json::from_str(&raw).context("failed to parse existing twak credentials json")?;
    Ok(parsed)
}

fn default_credentials_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".twak").join("credentials.json"))
}

fn generate_polygon_address() -> String {
    let secret = SecretKey::random(&mut OsRng);
    let signing_key = k256::ecdsa::SigningKey::from(secret);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let public_key = public_key.as_bytes();
    let hash = Keccak256::digest(&public_key[1..]);
    let address = &hash[12..];
    format!("0x{}", hex_lower(address))
}

fn ensure_address_query(raw_url: &str, address: &str) -> Result<String> {
    let mut url = Url::parse(raw_url).context("failed to parse Mercuryo URL")?;
    let has_address = url.query_pairs().any(|(key, _)| key == "address");
    if !has_address {
        url.query_pairs_mut().append_pair("address", address);
    }
    Ok(url.into())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

struct GatewayClient {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>,
    credentials: StoredCredentials,
}

impl GatewayClient {
    fn new(credentials: StoredCredentials) -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Self {
            client,
            credentials,
        }
    }

    async fn onramp_quote(
        &self,
        amount: &str,
        currency: &str,
        asset: &str,
        address: &str,
    ) -> Result<Vec<OnrampQuote>> {
        let path = format!("/v1/buycrypto/quote/{}", urlencoding::encode(asset));
        let query = sorted_query_string(&[
            ("amount", amount),
            ("currency", currency),
            ("address", address),
        ])?;
        let response: GatewayQuoteResponse = self.get_json(&path, &query).await?;
        Ok(response
            .quotes
            .into_iter()
            .map(|quote| OnrampQuote {
                quote_id: quote.id,
                provider: quote.provider.name,
            })
            .collect())
    }

    async fn onramp_buy(&self, quote_id: &str, address: &str) -> Result<BuyResponse> {
        let path = format!("/v1/buycrypto/request/{}", urlencoding::encode(quote_id));
        let query = sorted_query_string(&[("address", address)])?;
        let response: GatewayBuyResponse = self.get_json(&path, &query).await?;
        let url = response
            .url
            .or(response.redirect_url)
            .ok_or_else(|| anyhow!("no checkout url returned for quote {quote_id}"))?;
        Ok(BuyResponse { url })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str, query: &str) -> Result<T> {
        match self.get_json_once(path, query).await {
            Ok(value) => Ok(value),
            Err(err) if is_rate_limited(&err) => {
                sleep(Duration::from_secs(30)).await;
                self.get_json_once(path, query).await
            }
            Err(err) => Err(err),
        }
    }

    async fn get_json_once<T: for<'de> Deserialize<'de>>(&self, path: &str, query: &str) -> Result<T> {
        let uri = format!("{GATEWAY_BASE_URL}{path}?{query}");
        let date = fmt_http_date(SystemTime::now());
        let nonce = Uuid::new_v4().to_string();
        let signature = build_signature(
            Method::GET.as_str(),
            path,
            query,
            &self.credentials.access_id,
            &self.credentials.hmac_secret,
            &nonce,
            &date,
        )?;

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("X-TW-CREDENTIAL", self.credentials.access_id.as_str())
            .header("X-TW-NONCE", nonce)
            .header("X-TW-DATE", date)
            .header(AUTHORIZATION, HeaderValue::from_str(&format!("HMAC-SHA256 Signature={signature}"))?)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(Empty::<Bytes>::new())?;

        let response = self
            .client
            .request(request)
            .await
            .context("failed to call Trust Wallet gateway")?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .context("failed to read Trust Wallet response body")?
            .to_bytes();

        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            bail!("Trust Wallet gateway returned {}: {}", status, text.trim());
        }

        serde_json::from_slice(&body).context("failed to parse Trust Wallet gateway json")
    }
}

fn is_rate_limited(err: &anyhow::Error) -> bool {
    err.to_string().contains("429 Too Many Requests")
}

fn sorted_query_string(pairs: &[(&str, &str)]) -> Result<String> {
    let mut encoded = pairs
        .iter()
        .map(|(key, value)| Ok((urlencoding::encode(key), urlencoding::encode(value))))
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

fn build_signature(
    method: &str,
    path: &str,
    query: &str,
    access_id: &str,
    hmac_secret: &str,
    nonce: &str,
    date: &str,
) -> Result<String> {
    let plaintext = [method.to_uppercase(), path.to_string(), query.to_string(), access_id.to_string(), nonce.to_string(), date.to_string()].join(";");
    let mut mac =
        HmacSha256::new_from_slice(hmac_secret.as_bytes()).context("invalid hmac secret")?;
    mac.update(plaintext.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(signature))
}
