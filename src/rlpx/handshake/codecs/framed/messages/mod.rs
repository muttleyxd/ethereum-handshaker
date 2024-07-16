use std::fmt::Formatter;

use crate::rlpx::handshake::codecs::framed::messages::hello::Hello;

pub mod hello;

#[derive(Debug)]
pub enum Message {
    Hello(Hello),
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Hello(content) => write!(f, "Message::Hello: {content:#?}"),
        }
    }
}
