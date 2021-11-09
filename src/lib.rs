use sha3::{Digest, Keccak256};
use serde::{Serialize, Deserialize};

pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct SecpSignatureOffsets {
    pub signature_offset: u16, // offset to [signature,recovery_id] of 64+1 bytes
    pub signature_instruction_index: u8,
    pub eth_address_offset: u16, // offset to eth_address of 20 bytes
    pub eth_address_instruction_index: u8,
    pub message_data_offset: u16, // offset to start of message data
    pub message_data_size: u16,   // size of message data
    pub message_instruction_index: u8,
}

type Sig = (libsecp256k1::Signature, libsecp256k1::RecoveryId);

pub fn new_secp256k1_instruction(priv_keys: &[libsecp256k1::SecretKey], message_arr: &[u8]) {
    let secp_pubkeys: Vec<libsecp256k1::PublicKey> = priv_keys
        .iter()
        .map(|priv_key| libsecp256k1::PublicKey::from_secret_key(priv_key))
        .collect();

    let eth_pubkeys: Vec<[u8; HASHED_PUBKEY_SERIALIZED_SIZE]> = secp_pubkeys
        .iter()
        .map(|secp_pubkey| construct_eth_pubkey(&secp_pubkey))
        .collect();

    let mut hasher = Keccak256::new();
    hasher.update(&message_arr);
    let message_hash = hasher.finalize();
    let mut message_hash_arr = [0u8; 32];
    message_hash_arr.copy_from_slice(message_hash.as_slice());
    let message = libsecp256k1::Message::parse(&message_hash_arr);

    let sigs: Vec<Sig> = priv_keys
        .iter()
        .map(|priv_key| libsecp256k1::sign(&message, priv_key))
        .collect();
        
    let signature_arr = sigs[0].0.serialize();

    // let (signature, recovery_id) = libsecp256k1::sign(&message, priv_key);
    // let signature_arr = signature.serialize();
    // assert_eq!(signature_arr.len(), SIGNATURE_SERIALIZED_SIZE);

    // let mut instruction_data = vec![];
    // instruction_data.resize(
    //     DATA_START
    //         .saturating_add(eth_pubkey.len())
    //         .saturating_add(signature_arr.len())
    //         .saturating_add(message_arr.len())
    //         .saturating_add(1),
    //     0,
    // );
    // let eth_address_offset = DATA_START;
    // instruction_data[eth_address_offset..eth_address_offset.saturating_add(eth_pubkey.len())]
    //     .copy_from_slice(&eth_pubkey);

    // let signature_offset = DATA_START.saturating_add(eth_pubkey.len());
    // instruction_data[signature_offset..signature_offset.saturating_add(signature_arr.len())]
    //     .copy_from_slice(&signature_arr);

    // instruction_data[signature_offset.saturating_add(signature_arr.len())] =
    //     recovery_id.serialize();

    // let message_data_offset = signature_offset
    //     .saturating_add(signature_arr.len())
    //     .saturating_add(1);
    // instruction_data[message_data_offset..].copy_from_slice(message_arr);

    // let num_signatures = 1;
    // instruction_data[0] = num_signatures;
    // let offsets = SecpSignatureOffsets {
    //     signature_offset: signature_offset as u16,
    //     signature_instruction_index: 0,
    //     eth_address_offset: eth_address_offset as u16,
    //     eth_address_instruction_index: 0,
    //     message_data_offset: message_data_offset as u16,
    //     message_data_size: message_arr.len() as u16,
    //     message_instruction_index: 0,
    // };
    // let writer = std::io::Cursor::new(&mut instruction_data[1..DATA_START]);
    // bincode::serialize_into(writer, &offsets).unwrap();

    // Instruction {
    //     program_id: solana_sdk::secp256k1_program::id(),
    //     accounts: vec![],
    //     data: instruction_data,
    // }
}

pub fn construct_eth_pubkey(
    pubkey: &libsecp256k1::PublicKey,
) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&sha3::Keccak256::digest(&pubkey.serialize()[1..])[12..]);
    assert_eq!(addr.len(), HASHED_PUBKEY_SERIALIZED_SIZE);
    addr
}
