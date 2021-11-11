use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use solana_program::instruction::Instruction;

pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 13;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct SecpSignatureOffsets {
    pub signature_offset: u16, // offset to signatures
    pub signature_instruction_index: u8,
    pub recoveries_offset: u16,  // offset to recoveries
    pub eth_address_offset: u16, // offset to eth_addresses
    pub eth_address_instruction_index: u8,
    pub message_data_offset: u16, // offset to start of message data
    pub message_data_size: u16,   // size of message data
    pub message_instruction_index: u8,
}

pub fn new_secp256k1_instruction(
    priv_keys: &[libsecp256k1::SecretKey],
    message_arr: &[u8],
) -> Instruction {
    let number_of_signatures = priv_keys.len();

    let secp_pubkeys: Vec<_> = priv_keys
        .iter()
        .map(|priv_key| libsecp256k1::PublicKey::from_secret_key(priv_key))
        .collect();

    let eth_pubkeys: Vec<_> = secp_pubkeys
        .iter()
        .flat_map(|secp_pubkey| construct_eth_pubkey(&secp_pubkey))
        .collect();

    assert_eq!(
        eth_pubkeys.len(),
        number_of_signatures * HASHED_PUBKEY_SERIALIZED_SIZE
    );

    let mut hasher = Keccak256::new();
    hasher.update(&message_arr);
    let message_hash = hasher.finalize();
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(message_hash.as_slice());
    let message = libsecp256k1::Message::parse(&message_hash_arr);

    let sigs: Vec<_> = priv_keys
        .iter()
        .map(|priv_key| libsecp256k1::sign(&message, priv_key))
        .collect();

    let signature_arr: Vec<_> = sigs.iter().flat_map(|sig| sig.0.serialize()).collect();

    let recoveries_arr: Vec<_> = sigs.iter().map(|sig| sig.1.serialize()).collect();

    assert_eq!(
        signature_arr.len(),
        number_of_signatures * SIGNATURE_SERIALIZED_SIZE
    );

    assert_eq!(recoveries_arr.len(), number_of_signatures);

    let mut instruction_data = vec![];
    instruction_data.resize(
        DATA_START
            .saturating_add(eth_pubkeys.len())
            .saturating_add(signature_arr.len())
            .saturating_add(recoveries_arr.len())
            .saturating_add(message_arr.len())
            .saturating_add(1),
        0,
    );

    let eth_address_offset = DATA_START;
    instruction_data[eth_address_offset..eth_address_offset.saturating_add(eth_pubkeys.len())]
        .copy_from_slice(&eth_pubkeys);

    let signature_offset = DATA_START.saturating_add(eth_pubkeys.len());
    instruction_data[signature_offset..signature_offset.saturating_add(signature_arr.len())]
        .copy_from_slice(&signature_arr);

    let recoveries_offset = signature_offset.saturating_add(signature_arr.len());
    instruction_data[recoveries_offset..recoveries_offset.saturating_add(recoveries_arr.len())]
        .copy_from_slice(&recoveries_arr);

    let message_data_offset = recoveries_offset.saturating_add(recoveries_arr.len());
    instruction_data[message_data_offset..].copy_from_slice(message_arr);

    instruction_data[0] = number_of_signatures as u8;
    let offsets = SecpSignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: 0,
        recoveries_offset: recoveries_offset as u16,
        eth_address_offset: eth_address_offset as u16,
        eth_address_instruction_index: 0,
        message_data_offset: message_data_offset as u16,
        message_data_size: message_arr.len() as u16,
        message_instruction_index: 0,
    };

    let writer = std::io::Cursor::new(&mut instruction_data[1..DATA_START]);
    bincode::serialize_into(writer, &offsets).unwrap();

    Instruction {
        program_id: solana_sdk::secp256k1_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

pub fn construct_eth_pubkey(
    pubkey: &libsecp256k1::PublicKey,
) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&sha3::Keccak256::digest(&pubkey.serialize()[1..])[12..]);
    assert_eq!(addr.len(), HASHED_PUBKEY_SERIALIZED_SIZE);
    addr
}
