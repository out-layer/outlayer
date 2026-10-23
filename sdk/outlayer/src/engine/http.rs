//! JSON over HTTPS from the guest: `wasi:http` through `waki` on wasm, an error
//! anywhere else (the crate's own tests run natively and never send).

pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self, what: &str) -> Result<T, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("{what}: unreadable reply: {e}"))
    }
}

#[cfg(target_arch = "wasm32")]
pub fn post_json(url: &str, token: &str, body: &serde_json::Value) -> Result<Reply, String> {
    let response = waki::Client::new()
        .post(url)
        .header("Authorization", &format!("Bearer {token}"))
        .json(body)
        .send()
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = response.status_code();
    let body = response.body().map_err(|e| format!("reply from {url} unreadable: {e}"))?;
    Ok(Reply { status, body })
}

#[cfg(target_arch = "wasm32")]
pub fn get(url: &str, token: &str) -> Result<Reply, String> {
    let response = waki::Client::new()
        .get(url)
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = response.status_code();
    let body = response.body().map_err(|e| format!("reply from {url} unreadable: {e}"))?;
    Ok(Reply { status, body })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn post_json(url: &str, _token: &str, _body: &serde_json::Value) -> Result<Reply, String> {
    Err(format!("no HTTP outside wasm32 (asked for {url})"))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get(url: &str, _token: &str) -> Result<Reply, String> {
    Err(format!("no HTTP outside wasm32 (asked for {url})"))
}
