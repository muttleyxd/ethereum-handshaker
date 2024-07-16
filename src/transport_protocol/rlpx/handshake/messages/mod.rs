mod auth;
mod auth_ack;
mod hello;

use std::fmt::Formatter;

pub use auth::AuthRlp;
pub use auth_ack::AuthAck;
pub use hello::Hello;

#[derive(Debug)]
pub enum Message {
    Auth,
    AuthAck(AuthAck),
    Hello(Hello),
}

#[derive(Debug)]
pub enum MessageType {
    AuthAck,
}

// todo: strum?
impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Auth => f.write_str("Message::Auth"),
            Message::AuthAck(content) => write!(f, "Message::AuthAck: {content:#?}"),
            Message::Hello(content) => write!(f, "Message::Hello {content:#?}"),
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
