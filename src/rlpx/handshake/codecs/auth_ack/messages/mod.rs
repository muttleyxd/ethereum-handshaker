use std::fmt::Formatter;

use crate::rlpx::handshake::codecs::auth_ack::messages::auth_ack::AuthAck;

pub mod auth;
pub mod auth_ack;

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
            Self::Auth => f.write_str("Message::Auth"),
            Self::AuthAck(content) => write!(f, "Message::AuthAck: {content:#?}"),
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthAck => f.write_str("MessageType::AuthAck"),
        }
    }
}
