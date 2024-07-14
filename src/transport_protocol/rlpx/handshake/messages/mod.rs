mod auth;
mod auth_ack;

use std::fmt::Formatter;

pub use auth::AuthRlp;
pub use auth_ack::AuthAck;

#[derive(Debug)]
pub enum Message {
    Auth,
    AuthAck(AuthAck),
}

#[derive(Debug)]
pub enum MessageType {
    AuthAck,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Auth => f.write_str("Message::Auth"),
            Message::AuthAck(content) => write!(f, "Message::AuthAck: {content:#?}"),
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::AuthAck => f.write_str("MessageType::AuthAck"),
        }
    }
}
