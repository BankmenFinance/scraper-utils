use super::model::Signature;
use crate::schema::signatures::dsl::*;
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, PgConnection, QueryDsl, QueryResult, RunQueryDsl};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;

pub fn get_signature(
    connection: &mut PgConnection,
    tx_signature: &str,
) -> QueryResult<Vec<Signature>> {
    signatures::find(signatures, tx_signature).load::<Signature>(connection)
}

pub fn insert_signature_from_tx_status(
    connection: &mut PgConnection,
    confirmed_tx: &RpcConfirmedTransactionStatusWithSignature,
) -> QueryResult<usize> {
    let err = match &confirmed_tx.err {
        Some(e) => format!("{:?}", e),
        None => String::new(),
    };
    let tx_block_time = confirmed_tx
        .block_time
        .as_ref()
        .map(|bt| NaiveDateTime::from_timestamp_opt(*bt, 0).unwrap());
    diesel::insert_into(signatures)
        .values((
            signature.eq(confirmed_tx.signature.clone()),
            slot.eq(confirmed_tx.slot as i64),
            block_time.eq(tx_block_time),
            error.eq(err),
        ))
        .execute(connection)
}

pub fn insert_signature_from_confirmed_tx(
    connection: &mut PgConnection,
    tx_signature: &str,
    confirmed_tx: &EncodedConfirmedTransactionWithStatusMeta,
) -> QueryResult<usize> {
    let tx_block_time = confirmed_tx
        .block_time
        .as_ref()
        .map(|bt| NaiveDateTime::from_timestamp_opt(*bt, 0).unwrap());
    diesel::insert_into(signatures)
        .values((
            signature.eq(tx_signature.to_string()),
            slot.eq(confirmed_tx.slot as i64),
            block_time.eq(tx_block_time),
        ))
        .execute(connection)
}
