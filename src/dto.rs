pub struct Status {
    pub version: i64,
    pub network_id: NetworkId,
    pub total_difficulty: i64,
    pub block_hash: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub fork_identifier: ForkIdentifier,
}

pub enum NetworkId {
    Olympic,
    Frontier,
    MordenTestnet,
    RopstenTestnet,
    RinkebyTestnet,
    GoerliTestnet,
}

pub struct ForkIdentifier {
    pub hash: Vec<u8>,
    pub next: Vec<u8>,
}
