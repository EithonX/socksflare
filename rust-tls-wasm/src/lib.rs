use wasm_bindgen::prelude::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;
use std::sync::Arc;
use std::io::{Read, Write, Cursor};

#[wasm_bindgen]
pub struct WasmTlsClient {
    conn: ClientConnection,
}

#[wasm_bindgen]
impl WasmTlsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(hostname: &str) -> Result<WasmTlsClient, JsValue> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
            
        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(|e| JsValue::from_str(&format!("Invalid hostname: {}", e)))?
            .to_owned();
            
        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(WasmTlsClient { conn })
    }

    /// Feeds raw TCP bytes from the SOCKS5 proxy into the Rustls state machine.
    /// Returns the number of bytes consumed.
    pub fn provide_network_data(&mut self, data: &[u8]) -> Result<usize, JsValue> {
        let mut cursor = Cursor::new(data);
        let read = self.conn.read_tls(&mut cursor)
            .map_err(|e| JsValue::from_str(&format!("Rustls read error: {}", e)))?;
            
        self.conn.process_new_packets()
            .map_err(|e| JsValue::from_str(&format!("Rustls process packets error: {}", e)))?;
            
        Ok(read)
    }

    /// Extracts encrypted bytes that Rustls wants to send over the TCP socket.
    pub fn extract_network_data(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let mut buf = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut buf)
                .map_err(|e| JsValue::from_str(&format!("Rustls write_tls error: {}", e)))?;
        }
        Ok(js_sys::Uint8Array::from(buf.as_slice()))
    }

    /// Feeds plaintext application data to Rustls to be encrypted.
    pub fn write_app_data(&mut self, data: &[u8]) -> Result<(), JsValue> {
        self.conn.writer().write_all(data)
            .map_err(|e| JsValue::from_str(&format!("Rustls write_app_data error: {}", e)))?;
        Ok(())
    }

    /// Reads decrypted plaintext application data from Rustls.
    pub fn read_app_data(&mut self) -> Result<js_sys::Uint8Array, JsValue> {
        let mut plaintext = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(JsValue::from_str(&format!("Rustls read_app_data error: {}", e))),
            }
        }
        Ok(js_sys::Uint8Array::from(plaintext.as_slice()))
    }

    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }
    
    pub fn wants_read(&self) -> bool {
        self.conn.wants_read()
    }
    
    pub fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }
}
