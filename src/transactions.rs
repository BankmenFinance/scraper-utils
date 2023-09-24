//! This module contains helper methods to be used for processing transaction program logs.
use diesel::PgConnection;
use solana_client::{
    client_error::ClientError, nonblocking::rpc_client::RpcClient,
    rpc_client::GetConfirmedSignaturesForAddress2Config, rpc_config::RpcTransactionConfig,
    rpc_response::RpcConfirmedTransactionStatusWithSignature,
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    UiCompiledInstruction, UiTransactionEncoding,
};
use std::str::FromStr;

use crate::signatures::{
    get_signature, insert_signature_from_confirmed_tx, Signature as PgSignature,
};

/// Gets a transaction with the given signature.
///
/// # Returns
///
/// The return value will be the associated confirmed transaction.
///
/// # Errors
///
/// This function will echo errors encountered while performing the RPC request.
#[cfg_attr(feature = "profiling", tracing::instrument(skip(rpc_client)))]
#[allow(dead_code)]
pub async fn get_transaction(
    rpc_client: &RpcClient,
    signature: &Signature,
) -> Result<EncodedConfirmedTransactionWithStatusMeta, ClientError> {
    match rpc_client
        .get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: None,
            },
        )
        .await
    {
        Ok(t) => Ok(t),
        Err(e) => Err(e),
    }
}

/// Gets transaction statuses for the given Program Id.
///
/// # Behavior
///
/// If a last signature is provided, then transaction statuses only happening AFTER
/// the given signature will be fetched and returned.
///
/// This function will repeatedly RPC requests to fetch [`RpcConfirmedTransactionStatusWithSignature`]s,
/// therefore suitable access in the given [`RpcClient`] is expected.
///
/// # Returns
///
/// The return value will be all of the transaction statuses fetched from the RPC, this can be `THE ENTIRE`
/// history of transactions for a program that the RPC has stored `IF` a last signature is not provided.
///
/// # Errors
///
/// This function will echo errors encountered while performing RPC requests, even in cases where it
/// has already performed requests which have succeeded.
#[cfg_attr(feature = "profiling", tracing::instrument(skip(rpc_client)))]
#[allow(dead_code)]
pub async fn get_signatures(
    rpc_client: &RpcClient,
    last_signature: &Option<Signature>,
    program_id: Pubkey,
) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>, ClientError> {
    // Build the config for the initial RPC request.
    // We either want to request the 1000 last transaction statuses (this is the maximum limit) straight away
    // or we will simply fetch transaction statuses until the given `last_signature` is found.
    let mut config = if let Some(sig) = last_signature {
        log::info!("Fetching signatures until: {}", sig);
        GetConfirmedSignaturesForAddress2Config {
            until: Some(*sig),
            limit: Some(1000),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        }
    } else {
        log::info!("Fetching last 1000 signatures.");
        GetConfirmedSignaturesForAddress2Config {
            limit: Some(1000),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        }
    };

    // Fetch the transaction statuses with the config we built earlier.
    let mut signatures = match rpc_client
        .get_signatures_for_address_with_config(&program_id, config)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Err(e);
        }
    };
    // We reverse the vector because they come ordered by slot in a descending way.
    signatures.reverse();

    if last_signature.is_some() {
        return Ok(signatures);
    }

    let mut all_signatures = signatures.clone();
    // After reversing the received vector of transaction statuses, the first signature is the oldest one.
    let mut oldest_sig = Signature::from_str(&signatures.first().unwrap().signature).unwrap();

    log::info!("Fetching signatures before: {}", oldest_sig);

    loop {
        // Rebuild the config for the request before performing it.
        config = GetConfirmedSignaturesForAddress2Config {
            limit: Some(1000),
            commitment: Some(CommitmentConfig::confirmed()),
            before: Some(oldest_sig),
            ..Default::default()
        };

        // Fetch more transaction statuses!
        signatures = match rpc_client
            .get_signatures_for_address_with_config(&program_id, config)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Err(e);
            }
        };

        if signatures.is_empty() {
            log::info!("No more signatures found.");
            break;
        }

        log::info!("Fetched {} signatures.", signatures.len());
        // We reverse the vector because they come ordered by slot in a descending way.
        signatures.reverse();
        // After reversing the received vector of transaction statuses, the first signature is the oldest one.
        oldest_sig = Signature::from_str(&signatures.first().unwrap().signature).unwrap();
        log::info!("Fetching signatures before: {}", oldest_sig);
        // Slice the last transaction statuses we fetched with the vector containing all previously fetched
        // transaction statuses and then concatenate them.
        // This will result in a vector where they are ordered from oldest to latest transaction status.
        all_signatures = [signatures, all_signatures].concat();
    }

    Ok(all_signatures)
}

static SMPL_ID: &str = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu";
static PROGRAM_DATA: &str = "Program data: ";

/// Errors which are returned during execution of functions related to
/// processing transaction program logs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error parsing logs: {0}")]
    LogParseError(String),
    #[error(transparent)]
    DatabaseError(#[from] diesel::result::Error),
    #[error("Instruction Program Id could not be found in transaction account keys.")]
    ProgramIdNotFound,
}

/// Processes the given slice of [`RpcConfirmedTransactionStatusWithSignature`] for transaction logs of the given Program Id.
///
/// # Behavior
///
/// This function will repeatedly call [`get_transaction`] to fetch associated [`EncodedConfirmedTransactionWithStatusMeta`]s,
/// therefore suitable access in the given [`RpcClient`] is expected.
///
/// # Returns
///
/// The return value contains the transaction statuses for which there was an error while attempting to fetch the associated
/// confirmed transaction from the RPC.
///
/// # Errors
///
/// This function errors in two different occasions:
/// - if there is an error during [`process_transaction_logs`] it will be echoed so that this error can be treated
/// - if a [`PgConnection`] is provided and there is an error during the execution of a transaction or query
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip(connection, rpc_client, log_handler))
)]
#[allow(dead_code)]
pub async fn process_signatures<F>(
    connection: &mut Option<&mut PgConnection>,
    rpc_client: &RpcClient,
    signatures: &[RpcConfirmedTransactionStatusWithSignature],
    program_id: Pubkey,
    log_handler: F,
) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>, Error>
where
    F: Fn(
        &mut Option<&mut PgConnection>,
        &UiCompiledInstruction,
        &[String],
        &str,
    ) -> Result<(), Error>,
{
    let mut failed_signatures = Vec::new();

    for signature in signatures.iter() {
        let sig = Signature::from_str(&signature.signature).unwrap();

        log::info!("Processing signature: {:?}", sig);

        // Get the transaction.
        let tx = match get_transaction(rpc_client, &sig).await {
            Ok(t) => t,
            Err(e) => {
                log::error!(
                    "Failed to fetch transaction with signature: {:?}. Error: {:?}",
                    sig,
                    e
                );
                failed_signatures.push(signature.clone());
                continue;
            }
        };

        // Process the transaction logs for the given Program Id.
        match process_transaction_logs(connection, &tx, program_id, &log_handler) {
            Ok(num_events) => {
                log::info!(
                    "Successfully processed {} events from transaction.",
                    num_events
                );
            }
            Err(e) => {
                return Err(e);
            }
        };

        // If we have a `PgConnection`, this is where we will attempt to fetch the signature
        // and if we can't find it we will attempt inserting it using the schemas defined in this crate.
        if let Some(connection) = connection.as_mut() {
            log::info!(
                "Found database connection. Attempting to fetch matching signature in database.."
            );
            let signatures: Vec<PgSignature> = match get_signature(connection, &sig.to_string()) {
                Ok(s) => s,
                Err(e) => {
                    return Err(Error::DatabaseError(e));
                }
            };

            if signatures.is_empty() {
                log::info!("Could not find matching signature in database, inserting..");
                match insert_signature_from_confirmed_tx(connection, &sig.to_string(), &tx) {
                    Ok(n) => {
                        log::info!("Sucessfully inserted {} entries.", n);
                    }
                    Err(e) => {
                        return Err(Error::DatabaseError(e));
                    }
                };
            }
        }
    }

    Ok(failed_signatures)
}

/// Processes the [`EncodedConfirmedTransactionWithStatusMeta`] for transaction logs of the given Program Id.
///
/// # Behavior
///
/// If the confirmed transaction does not have program logs, it will return instantly.
///
/// If the confirmed transaction has program logs, this function will iterate through them and attempt to capture
/// anchor events in order to call the given log handler function.
///
/// # Returns
///
/// The return value represents the number of times an event was found and the log handler was successfully called.
///
/// # Errors
///
/// This function errors in two different occasions:
/// - if it can't find the given Program Id within the transaction's account keys.
/// - if the given log handler errors, this function will echo the error.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip(connection, log_handler))
)]
#[allow(dead_code)]
pub fn process_transaction_logs<F>(
    connection: &mut Option<&mut PgConnection>,
    tx_meta: &EncodedConfirmedTransactionWithStatusMeta,
    program_id: Pubkey,
    log_handler: F,
) -> Result<usize, Error>
where
    F: Fn(
        &mut Option<&mut PgConnection>,
        &UiCompiledInstruction,
        &[String],
        &str,
    ) -> Result<(), Error>,
{
    // Try to get the transaction logs, if we can't find them we can return instantly.
    let logs = if let Some(meta) = &tx_meta.transaction.meta {
        match &meta.log_messages {
            OptionSerializer::Some(l) => l.clone(),
            _ => {
                log::info!("Transaction without log messages.");
                return Ok(0);
            }
        }
    } else {
        return Ok(0);
    };

    let mut processed_events = 0;

    // Check if there are actually logs to process.
    if !logs.is_empty() {
        log::info!("Found {} log messages.", logs.len());
        let mut rem_logs = logs.clone();

        // This is where things get a bit trickier, this is the only transaction encoding that effectively allows
        // us to get a deep look at both the logs, accounts present in the transaction and instructions and their data.
        if let solana_transaction_status::EncodedTransaction::Json(ui_tx) =
            &tx_meta.transaction.transaction
        {
            match &ui_tx.message {
                solana_transaction_status::UiMessage::Raw(r) => {
                    log::debug!("UiMessageRaw: {:?}", r);

                    let instruction_count = r.instructions.len();
                    log::debug!("Instruction Count: {}", instruction_count);

                    for (ix_idx, ix) in r.instructions.iter().enumerate() {
                        log::debug!("Logs: {:?}", rem_logs);
                        match handle_compiled_instruction(
                            connection,
                            ix,
                            &r.account_keys,
                            &rem_logs,
                            &program_id,
                            &log_handler,
                        ) {
                            Ok(idx) => {
                                // This value is the index into the previously split program logs where an event was found.
                                // So this is where we are going to split the remaining logs before continuing to iterate.
                                if idx != 0 {
                                    log::debug!("Event Log Index: {}", idx);
                                    let (_, split_rem_logs) = rem_logs.split_at(idx + 1);
                                    rem_logs = split_rem_logs.to_vec();
                                    processed_events += 1;
                                    continue;
                                }
                                log::debug!("Found no events for instruction {}", ix_idx);
                            }
                            Err(e) => {
                                // If we fail to process the instruction, we will simply return with the error
                                // so that this can be handled on the caller and there can be an attempt to reprocess.
                                return Err(e);
                            }
                        }
                    }
                }
                solana_transaction_status::UiMessage::Parsed(p) => {
                    log::debug!("UiMessageParsed: {:?}", p);

                    let instruction_count = p.instructions.len();
                    log::debug!("Instruction Count: {}", instruction_count);

                    // Map the `UiParsedMessage`'s account keys from `ParsedAccount` to a vector of strings
                    // that we can pass as a slice into the `handle_compiled_instruction` handler.
                    let tx_account_keys = p
                        .account_keys
                        .iter()
                        .map(|a| a.pubkey.clone())
                        .collect::<Vec<String>>();

                    for (ix_idx, ix) in p.instructions.iter().enumerate() {
                        match ix {
                            solana_transaction_status::UiInstruction::Compiled(ui_compiled_ix) => {
                                match handle_compiled_instruction(
                                    connection,
                                    ui_compiled_ix,
                                    &tx_account_keys,
                                    &rem_logs,
                                    &program_id,
                                    &log_handler,
                                ) {
                                    Ok(idx) => {
                                        // This value is the index into the previously split program logs where an event was found.
                                        // So this is where we are going to split the remaining logs before continuing to iterate.
                                        if idx != 0 {
                                            log::debug!("Event Log Index: {}", idx);
                                            let (_, split_rem_logs) = rem_logs.split_at(idx + 1);
                                            rem_logs = split_rem_logs.to_vec();
                                            processed_events += 1;
                                            continue;
                                        }
                                        log::debug!("Found no events for instruction {}", ix_idx);
                                    }
                                    Err(e) => {
                                        // If we fail to process the instruction, we will simply return with the error
                                        // so that this can be handled on the caller and there can be an attempt to reprocess.
                                        return Err(e);
                                    }
                                }
                            }
                            _ => {
                                log::error!("Unsupported Transaction Meta encoding: {:?}", tx_meta);
                            }
                        }
                    }
                }
            }
        } else {
            log::error!("Unsupported Transaction Meta encoding: {:?}", tx_meta);
        };
    }
    Ok(processed_events)
}

/// This function is used when processing transaction logs, it can and will likely be called multiple times
/// for the same [`EncodedConfirmedTransactionWithStatusMeta`].
///
/// # Behavior
///
/// For the given [`UiCompiledInstruction`], account keys and remaining logs associated,
/// this method checks that the provided Program Id is present in the account keys,
/// and if it is, it will iterate through the available remaining transaction program logs
/// to check if they represent an anchor event.
///
/// In the case where it finds a program log which is an anchor event, the given log handler function is called.
///
/// # Returns
///
/// The return value is the index into the given remaining program logs at which the program log
/// resulting in a call to the given log handler was found.
///
///
/// # Errors
///
/// This function errors in two different occasions:
/// - if it can't find the given Program Id within the transaction's account keys.
/// - if the given log handler errors, this function will echo the error.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip(connection, log_handler))
)]
fn handle_compiled_instruction<F>(
    connection: &mut Option<&mut PgConnection>,
    ix: &UiCompiledInstruction,
    tx_account_keys: &[String],
    tx_remaining_logs: &[String],
    check_program_id: &Pubkey,
    log_handler: &F,
) -> Result<usize, Error>
where
    F: Fn(
        &mut Option<&mut PgConnection>,
        &UiCompiledInstruction,
        &[String],
        &str,
    ) -> Result<(), Error>,
{
    // Get the Program Id of the instruction whose transaction logs we want to process.
    // If we can't find the Program Id in the provided transaction account keys, we error out.
    let ix_program_id = match &tx_account_keys
        .iter()
        .enumerate()
        .find(|(idx, _)| *idx == ix.program_id_index as usize)
    {
        Some((_, account_key)) => *account_key,
        None => return Err(Error::ProgramIdNotFound),
    };

    // We perform a check for the provided Program Id and the Squads Multisig Program Id.
    // This way we do not miss events which might be emitted when executing transactions through Squads.
    if !(ix_program_id == &check_program_id.to_string() || ix_program_id == SMPL_ID) {
        // If the instruction's Program Id does not match either the provided Program Id or the Squads Multisig Program Id
        // we return earlier.
        log::debug!("Program ID does not match target or SMPL.");
        // Returning zero as a value here is because we did not process any logs, so there is no need for the caller
        // to split the remaining logs before attempting to invoke the callee again to process the next instruction.
        return Ok(0);
    }

    // We are going to iterate the provided remaining logs associated with this instruction and if we find
    // a program log that represents an anchor event, we will call the given log handler function so that the log can be processed.

    for (log_idx, l) in tx_remaining_logs.iter().enumerate() {
        log::info!("Log: {}", l);

        if let Some(event_log) = l.strip_prefix(PROGRAM_DATA) {
            match log_handler(connection, ix, tx_account_keys, event_log) {
                Ok(()) => return Ok(log_idx),
                Err(e) => return Err(e),
            }
        } else {
            continue;
        }
    }
    log::debug!("Processed all logs..");
    Ok(0)
}
