use std::time::Duration;

use axum::body::Bytes;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use tokio::{select, signal};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{error, info, warn};
use tokio::sync::{mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_tls_with_config, WebSocketStream};

// const SUB: Message = Message::Text(r#"{"jsonrpc":"2.0","method":"subscribe","id":0,"params":{"query":"tm.event='NewBlock'"}}"#.to_string().into());
// 
/// WebSocket client structure for handling secure WebSocket connections.
///
/// This client supports TLS/SSL secure connections and provides a simple interface
/// for sending and receiving messages. It is optimized for performance with features like:
/// - Binary message support
/// - Connection timeout handling
/// - Certificate caching
/// - Auto-reconnection capabilities
/// - Optimized memory usage
///
/// # Example
///
/// ```ignore
/// use ws_rs::client::WebSocketClient;
/// use ws_rs::client::MessageType;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Create a client with custom configuration
///     let mut client = WebSocketClient::builder()
///         .with_channel_capacity(200)
///         .with_connection_timeout(Duration::from_secs(10))
///         .with_auto_reconnect(true)
///         .build();
///
///     // Connect to a WebSocket server
///     client.connect(
///         "wss://127.0.0.1:9000",
///         "./certs",
///         "client_cert.pem",
///         "client_key.pem",
///         "ca_cert.pem"
///     ).await?;
///
///     // Send a text message
///     client.send_message(MessageType::Text("Hello, server!".to_string())).await?;
///
///     // Send a binary message
///     client.send_message(MessageType::Binary(vec![1, 2, 3, 4])).await?;
///
///     // Receive a message
///     if let Some(response) = client.receive_message().await {
///         match response {
///             MessageType::Text(text) => println!("Received text: {}", text),
///             MessageType::Binary(data) => println!("Received binary data: {} bytes", data.len()),
///         }
///     }
///
///     // Close the connection
///     client.close().await;
///
///     Ok(())
/// }
/// ```
/// Message type enum for WebSocket communication
#[derive(Debug, Clone)]
pub enum MessageType {
    /// Text message
    Text(String),
    /// Binary message
    Binary(Vec<u8>),
}

/// Configuration for WebSocketClient
#[derive(Debug, Clone)]
pub struct WSClientConfig {
    /// Channel capacity for message queues
    pub channel_capacity: usize,
    /// Connection timeout in seconds
    pub connection_timeout: Duration,
    /// Whether to automatically reconnect on connection failure
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
    /// Delay between reconnection attempts
    pub reconnect_delay: Duration,
}

impl Default for WSClientConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 100,
            connection_timeout: Duration::from_secs(30),
            auto_reconnect: false,
            max_reconnect_attempts: 5,
            reconnect_delay: Duration::from_secs(2),
        }
    }
}

/// Builder for WebSocketClient
pub struct WebSocketClientBuilder {
    config: WSClientConfig,
}

impl WebSocketClientBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: WSClientConfig::default(),
        }
    }

    /// Set channel capacity
    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.config.channel_capacity = capacity;
        self
    }

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.connection_timeout = timeout;
        self
    }

    /// Enable or disable auto-reconnect
    pub fn with_auto_reconnect(mut self, auto_reconnect: bool) -> Self {
        self.config.auto_reconnect = auto_reconnect;
        self
    }

    /// Set maximum reconnection attempts
    pub fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.config.max_reconnect_attempts = attempts;
        self
    }

    /// Set delay between reconnection attempts
    pub fn with_reconnect_delay(mut self, delay: Duration) -> Self {
        self.config.reconnect_delay = delay;
        self
    }

    /// Build the WebSocketClient with the configured options
    pub fn build(self) -> WebSocketClient {
        WebSocketClient {
            sender: None,
            receiver: None,
            ws_handle: None,
            is_connected: false,
            server_url: "".to_owned(),
            config: self.config,
        }
    }
}

pub struct WebSocketClient {
    sender: Option<mpsc::Sender<Message>>,
    receiver: Option<SplitStream<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>>,
    ws_handle: Option<JoinHandle<()>>,
    is_connected: bool,
    server_url: String,
    config: WSClientConfig,
}

impl WebSocketClient {
    /// Creates a new WebSocketClient instance with default configuration.
    ///
    /// The new client is initially disconnected. Use the `connect` method
    /// to establish a connection to a WebSocket server.
    ///
    /// # Returns
    ///
    /// A new `WebSocketClient` instance.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Creates a builder for configuring a WebSocketClient.
    ///
    /// # Returns
    ///
    /// A WebSocketClientBuilder instance.
    pub fn builder() -> WebSocketClientBuilder {
        WebSocketClientBuilder::new()
    }

    /// Connects to a WebSocket server using TLS.
    ///
    /// This method establishes a secure WebSocket connection to the specified server URL
    /// using the provided certificates and keys.
    ///
    /// # Parameters
    ///
    /// * `server_url` - The WebSocket server URL (e.g., "wss://example.com:9000")
    /// * `cert_dir` - Directory containing the certificate files
    /// * `client_cert_file` - Client certificate filename
    /// * `client_key_file` - Client private key filename
    /// * `ca_cert_file` - CA certificate filename
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful connection, or an error if the connection fails.
    ///
    /// # Errors
    ///
    /// Returns an error if URL parsing fails, certificate loading fails, or connection fails.
    pub async fn connect(
        &mut self,
        server_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Save connection parameters for potential reconnection
        self.server_url = server_url.clone();


        // let ser = server_url;
        loop {
            select! {
                result = self.connect_internal(&server_url, 0) => match result{
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(e) => {
                        error!("Connection attempt failed: {}", e);
                        tokio::time::sleep(self.config.reconnect_delay).await;
                        continue;
                    }
                },
                _ = signal::ctrl_c() => {
                    info!("Cancel reconnecting and exit.");
                    std::process::exit(0)
                },
            }

        }
    }

    /// Internal connect method that handles reconnection attempts
    ///
    /// This function uses manual reconnection logic instead of recursive calls
    /// to avoid boxing issues with async functions.
    async fn connect_internal(
        &mut self,
        server_url: &String,
        attempt: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
 
        // Connect to WebSocket server with timeout
        tracing::info!("Connecting to WebSocket server: {}", server_url);

        // Create WebSocket request with proper headers
        let request = server_url.as_str().into_client_request()?;

        // Use timeout for connection attempt
        let connection_attempt =
            connect_async_tls_with_config(request, None, false, None);
        let ws_stream = match timeout(self.config.connection_timeout, connection_attempt).await {
            Ok(result) => {
                match result {
                    Ok((stream, _response)) => {
                        stream
                    }
                    Err(e) => {
                        error!("Connection error: {}", e);

                        warn!(
                            "Reconnection attempt {} in {}s",
                            attempt + 1,
                            self.config.reconnect_delay.as_secs()
                        );

                        // Wait before attempting to reconnect
                        tokio::time::sleep(self.config.reconnect_delay).await;

                        return Err(e.into());
                    }
                }
            }
            Err(_) => {
                let err = format!(
                    "Connection timeout after {:?}",
                    self.config.connection_timeout
                );
                error!("{}", err);

                // Handle reconnection if enabled
                if self.config.auto_reconnect && attempt < self.config.max_reconnect_attempts {
                    warn!(
                        "Reconnection attempt {}/{} in {}s",
                        attempt + 1,
                        self.config.max_reconnect_attempts,
                        self.config.reconnect_delay.as_secs()
                    );

                    // Wait before attempting to reconnect
                    tokio::time::sleep(self.config.reconnect_delay).await;

                    // Rather than making a recursive call, we'll return a special error
                    // that indicates we should retry the connection
                    return Err(format!("__RETRY_CONNECTION_{}", attempt + 1).into());
                }

                return Err(err.into());
            }
        };

        info!("Connected to WebSocket server");

        // let (tx_receiver, rx_receiver) = mpsc::channel::<Message>(self.config.channel_capacity);

        // Split connection into sender and receiver
        let (mut ws_sender, ws_receiver) = ws_stream.split();


        let _x = ws_sender.send(Message::Text(r#"{"jsonrpc":"2.0","method":"subscribe","id":0,"params":{"query":"tm.event='NewBlock'"}}"#.to_string().into())).await;

        // Task for handling incoming messages
        // let receive_task = tokio::spawn(async move {
        //     while let Some(msg) = ws_receiver.next().await {
        //         // let m = msg.unwrap();
        //         if let Err(_) = tx_receiver.send(msg.unwrap()).await {
        //             // Channel closed - receiver has been dropped, which is normal during shutdown
        //             debug!("Receiver channel closed, stopping message forwarding");
        //             break;
        //         }
        //     }
        // });

        // Combine tasks with select to handle termination
        // let handle = tokio::spawn(async move {
        //     tokio::select! {
        //         _ = send_task => Ok(()),
        //         re = receive_task => {
        //             match re {
        //                 Ok(_) => Ok(()),
        //                 Err(e) => return Err(e),
        //             }
        //         }
        //     }
        // });

        // Update client state
        // self.sender = Some(tx_sender);
        self.receiver = Some(ws_receiver);
        // self.ws_handle = Some(receive_task);
        self.is_connected = true;

        Ok(())
    }

    /// Reconnects to the WebSocket server using the last connection parameters.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful reconnection, or an error if reconnection fails.
    ///
    /// # Errors
    ///
    /// Returns an error if no previous connection exists or if reconnection fails.
    pub async fn reconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {

        if self.is_connected {
            self.close().await;
        }

        // Connect using saved parameters
        self.connect(self.server_url.clone()).await

    }

    /// Receives a message from the WebSocket server.
    ///
    /// This method waits for the next message from the server. If no message
    /// is available or the connection is closed, it returns `None`.
    ///
    /// # Returns
    ///
    /// * `Some(MessageType)` - The received message (text or binary)
    /// * `None` - If not connected or the connection was closed
    pub async fn receive_message(&mut self) -> Option<std::result::Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>> {
        if let Some(receiver) = &mut self.receiver {
            receiver.next().await 
        } else {
            None
        }
    }

    /// Receives a message with timeout.
    ///
    /// This method waits for the next message from the server with a timeout.
    ///
    /// # Parameters
    ///
    /// * `timeout_duration` - Maximum time to wait for a message
    ///
    /// # Returns
    ///
    /// * `Ok(Some(MessageType))` - A message was received
    /// * `Ok(None)` - No message received (not connected)
    /// * `Err(_)` - Timeout occurred
    // pub async fn receive_message_timeout(
    //     &mut self,
    //     timeout_duration: Duration,
    // ) -> Result<Option<Message>, tokio::time::error::Elapsed> {
    //     if let Some(receiver) = &mut self.receiver {
    //         timeout(timeout_duration, receiver.recv()).await
    //     } else {
    //         Ok(None)
    //     }
    // }

    /// Checks if the client is connected to a WebSocket server.
    ///
    /// # Returns
    ///
    /// `true` if connected, `false` otherwise.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Closes the WebSocket connection.
    ///
    /// This method gracefully shuts down the connection by:
    /// 1. Dropping the sender channel to trigger closing the WebSocket
    /// 2. Waiting for the worker task to complete
    /// 3. Cleaning up resources
    ///
    /// The client can be reconnected after closing by calling `connect()` again.
    pub async fn close(&mut self) {
        // Drop the sender channel to trigger close operation
        self.sender = None;

        // Wait for the main task to complete
        if let Some(handle) = self.ws_handle.take() {
            let _ = handle.await;
        }

        self.receiver = None;
        self.is_connected = false;

        info!("WebSocket connection closed");
    }

    /// Sends a ping message to check connection health.
    ///
    /// This method can be used to keep the connection alive or
    /// check if the server is still responsive.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the ping was sent, or an error if not connected.
    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(sender) = &self.sender {
            // Use an empty binary message as a ping
            sender.send(Message::Binary(Bytes::new())).await?;
            Ok(())
        } else {
            Err("Not connected to WebSocket server".into())
        }
    }

    /// Checks if a connection is active and sends a ping to verify connectivity.
    ///
    /// Returns true if the connection is active and responsive.
    pub async fn check_connection(&self) -> bool {
        if !self.is_connected {
            return false;
        }

        match self.ping().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Gets the current configuration.
    ///
    /// # Returns
    ///
    /// A reference to the current client configuration.
    pub fn get_config(&self) -> &WSClientConfig {
        &self.config
    }
}

impl Drop for WebSocketClient {
    fn drop(&mut self) {
        // If the client is still connected when going out of scope,
        // drop all channels to allow resources to be cleaned up
        self.sender = None;
        self.receiver = None;

        // Drop the task handle, allowing it to complete on its own
        self.ws_handle = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type() {
        let text = MessageType::Text("hello".to_string());
        let binary = MessageType::Binary(vec![1, 2, 3]);

        match text {
            MessageType::Text(s) => assert_eq!(s, "hello"),
            _ => panic!("Expected Text variant"),
        }

        match binary {
            MessageType::Binary(b) => assert_eq!(b, vec![1, 2, 3]),
            _ => panic!("Expected Binary variant"),
        }
    }

    #[test]
    fn test_client_config_default() {
        let config = WSClientConfig::default();
        assert_eq!(config.channel_capacity, 100);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.auto_reconnect, false);
    }

    #[tokio::test]
    async fn test_client_builder() {
        let mut client = WebSocketClient::builder()
            .with_channel_capacity(200)
            .with_connection_timeout(Duration::from_secs(10))
            .with_auto_reconnect(true)
            .build();

        assert_eq!(client.config.channel_capacity, 200);
        assert_eq!(client.config.connection_timeout, Duration::from_secs(10));
        assert_eq!(client.config.auto_reconnect, true);

        let _ = client.connect("ws://localhost:26657/websocket".to_string()).await;

    }
}