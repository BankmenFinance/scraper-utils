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
#[derive(Debug, PartialEq, thiserror::Error)]
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
                            Ok((last_index, logs_handled)) => {
                                // This value is the index into the previously split program logs that was last processed
                                // So this is where we are going to split the remaining logs before continuing to iterate over the instructions.
                                if last_index != 0 {
                                    log::debug!(
                                        "Event Logs Handled: {} - Last Index: {}",
                                        logs_handled,
                                        last_index
                                    );
                                    let (_, split_rem_logs) = rem_logs.split_at(last_index + 1);
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
                                    Ok((last_index, logs_handled)) => {
                                        // This value is the index into the previously split program logs that was last processed
                                        // So this is where we are going to split the remaining logs before continuing to iterate over the instructions.
                                        if last_index != 0 {
                                            log::debug!(
                                                "Event Logs Handled: {} - Last Index: {}",
                                                logs_handled,
                                                last_index
                                            );
                                            let (_, split_rem_logs) =
                                                rem_logs.split_at(last_index + 1);
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
) -> Result<(usize, usize), Error>
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
        .find(|(_, key)| *key == &check_program_id.to_string())
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
        return Ok((0, 0));
    }

    // We are going to iterate the provided remaining logs associated with this instruction and if we find
    // a program log that represents an anchor event, we will call the given log handler function so that the log can be processed.

    let mut invoke_stack = Vec::new();
    let mut logs_handled = 0;

    for (log_idx, l) in tx_remaining_logs.iter().enumerate() {
        println!("Log: {}", l);

        let log_split = l.split(" ").collect::<Vec<&str>>();

        // if the log contains "Program" and "invoke" then we know that the second string is the program id being invoked
        // we'll add this program id to a stack so we can keep track of inner invocations
        if l.contains("Program") && l.contains("invoke") {
            invoke_stack.push(log_split[1]);
        }

        if let Some(event_log) = l.strip_prefix(PROGRAM_DATA) {
            match log_handler(connection, ix, tx_account_keys, event_log) {
                Ok(()) => {
                    logs_handled += 1;
                }
                Err(e) => return Err(e),
            }
        }

        // if the log contains "Program" and "success" then we know that this invocation is now over
        //
        if l.contains("Program") && l.contains("success") {
            invoke_stack.pop();
        }

        // if the invocation stack is empty
        // then that means we've processed this instruction and thus we should return
        if invoke_stack.is_empty() {
            return Ok((log_idx, logs_handled));
        }
    }
    println!("Processed all logs..");
    Ok((0, 0))
}

mod tests {
    use super::*;
    use crate::Error;
    use solana_transaction_status::UiCompiledInstruction;

    #[allow(dead_code)]
    fn get_tx_1_logs() -> Vec<String> {
        return vec![
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW invoke [1]".to_string(),
            "Program log: Instruction: OfferLoan".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
            "Program log: Instruction: InitializeAccount3".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3158 of 162682 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: ehxky17/XPgiVr33CnxXF/0y7MgdsKjnpziiexE8xoCZ/X8lUtyO1t3C+ojU/DbGbFgVIZZKo0qvcIA1NDD4N4RuLnpFsbcpBpuIV/6rgYT7aH9jRhjANdrEOdwa6ztVmKDwAAAAAAFhI1zgO4Oswp/RdsH5+K3ClO5A3+x8X4u1dSuDExC5tnTGOwmpl+Gg3cuaPnIuh9xMYsXW9UDo8+khKmxTOOjaAMqaOwAAAAABASwB".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW consumed 55100 of 200000 compute units".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW success".to_string(),
        ];
    }

    #[allow(dead_code)]
    fn get_tx_2_logs() -> Vec<String> {
        return vec![
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW invoke [1]".to_string(),
            "Program log: Instruction: TakeLoan".to_string(),
            "Program log: Token Standard: Legacy".to_string(),
            "Program log: Loan Type: Simple".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
            "Program log: Instruction: Approve".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2904 of 267771 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program log: Freezing Legacy NFT.".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s invoke [2]".to_string(),
            "Program log: IX: Freeze Delegated Account".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [3]".to_string(),
            "Program log: Instruction: FreezeAccount".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4310 of 247723 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s consumed 18482 of 261244 compute units".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s success".to_string(),
            "Program log: Froze Legacy NFT.".to_string(),
            "Program log: Transferring funds to borrower for 100000000 native units of Loan Token Mint.".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW consumed 67794 of 300000 compute units".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW success".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW invoke [1]".to_string(),
            "Program log: Instruction: TakeLoan".to_string(),
            "Program log: Token Standard: Legacy".to_string(),
            "Program log: Loan Type: Simple".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
            "Program log: Instruction: Approve".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2904 of 199977 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program log: Freezing Legacy NFT.".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s invoke [2]".to_string(),
            "Program log: IX: Freeze Delegated Account".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [3]".to_string(),
            "Program log: Instruction: FreezeAccount".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4310 of 181429 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s consumed 16982 of 193450 compute units".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s success".to_string(),
            "Program log: Froze Legacy NFT.".to_string(),
            "Program log: Transferring funds to borrower for 50000000 native units of Loan Token Mint.".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DQV4rcNvw+46jMn8gQ7LlBz3zKDZdT7eFLRfrXkylzR/pi9RmDXKCaut29g2py0MZyonZmC+VUgrbYb4b0+A4KSCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAAC4kwEDAAAAAIDw+gIAAAAA".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW consumed 66278 of 232206 compute units".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW success".to_string(),
          ];
    }

    #[allow(dead_code)]
    fn get_tx_3_logs() -> Vec<String> {
        return vec![
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program ComputeBudget111111111111111111111111111111 invoke [1]".to_string(),
            "Program ComputeBudget111111111111111111111111111111 success".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW invoke [1]".to_string(),
            "Program log: Instruction: TakeLoan".to_string(),
            "Program log: Token Standard: Legacy".to_string(),
            "Program log: Loan Type: Simple".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
            "Program log: Instruction: Approve".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2904 of 267771 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program log: Freezing Legacy NFT.".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s invoke [2]".to_string(),
            "Program log: IX: Freeze Delegated Account".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [3]".to_string(),
            "Program log: Instruction: FreezeAccount".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4310 of 247723 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s consumed 18482 of 261244 compute units".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s success".to_string(),
            "Program log: Froze Legacy NFT.".to_string(),
            "Program log: Transferring funds to borrower for 100000000 native units of Loan Token Mint.".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW consumed 67794 of 300000 compute units".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW success".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW invoke [1]".to_string(),
            "Program log: Instruction: TakeLoan".to_string(),
            "Program log: Token Standard: Legacy".to_string(),
            "Program log: Loan Type: Simple".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
            "Program log: Instruction: Approve".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2904 of 199977 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program log: Freezing Legacy NFT.".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s invoke [2]".to_string(),
            "Program log: IX: Freeze Delegated Account".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [3]".to_string(),
            "Program log: Instruction: FreezeAccount".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4310 of 181429 compute units".to_string(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DcYk55fH15kF/mzUo6fmGs4q/N++QUm0Lg/CswTp0SV4pwT5ktBrp9/VPW7gwYwll5VNst+vOE/l43qLuoiba4GCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAABwJwMGAAAAAADh9QUAAAAA".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s consumed 16982 of 193450 compute units".to_string(),
            "Program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s success".to_string(),
            "Program log: Froze Legacy NFT.".to_string(),
            "Program log: Transferring funds to borrower for 50000000 native units of Loan Token Mint.".to_string(),
            "Program 11111111111111111111111111111111 invoke [2]".to_string(),
            "Program 11111111111111111111111111111111 success".to_string(),
            "Program data: Pkx/rX/Hh4s4as/aLoeQzk3pqvMJWbkB+4pUWF/hfVFUXPmCb/+1DQV4rcNvw+46jMn8gQ7LlBz3zKDZdT7eFLRfrXkylzR/pi9RmDXKCaut29g2py0MZyonZmC+VUgrbYb4b0+A4KSCAsChynRJiNh6lqpEx7f7RjyNHqILKslZT8iWInqk41GS+33LjRHmLT7n2lFMOCpvC6+qA7itxPeO2kgLJeCA9sIRZQAAAAC4kwEDAAAAAIDw+gIAAAAA".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW consumed 66278 of 232206 compute units".to_string(),
            "Program BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW success".to_string(),
          ];
    }

    #[allow(dead_code)]
    fn get_tx_1_accounts() -> Vec<String> {
        return vec![
            "7YBpfGJi2kEYJNkZBJn9j5we4HHzjJy2KZ155mEe5udo".to_string(),
            "3K3aTU78GCtzEDBJcuPPSQjUF7aoq5As2jZnMi2dtTch".to_string(),
            "5kTog8xPUiVpwswQFSPNbxTJ7JVpaazfgR8djNoeD5eQ".to_string(),
            "8rqcL29F1UuwFNhubmeckZAKqpWwBr1UgiAP2yKJxpg1".to_string(),
            "AKLXBVd4Ft3WreQTej5zwrj59UTSFTdrhnsQYuJ9E3yd".to_string(),
            "F9MrguGEAnQjuZNwKNRhmN2th6D9xz4UJUNMv98UaeRJ".to_string(),
            "FvfYPyUnNfsiF8XYrxTgHTji6NeVM1r5ierCbqg6m2wz".to_string(),
            "11111111111111111111111111111111".to_string(),
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".to_string(),
            "BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW".to_string(),
            "ComputeBudget111111111111111111111111111111".to_string(),
            "So11111111111111111111111111111111111111112".to_string(),
            "SysvarRent111111111111111111111111111111111".to_string(),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
        ];
    }

    #[allow(dead_code)]
    fn log_handler(
        _connection: &mut Option<&mut PgConnection>,
        ix: &UiCompiledInstruction,
        _accounts: &[String],
        _log: &str,
    ) -> Result<(), Error> {
        println!("{:?}", ix);
        Ok(())
    }

    #[test]
    fn test_handle_compiled_instruction_err() -> Result<(), Error> {
        let logs = get_tx_1_logs();

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: String::new(),
                stack_height: Some(1),
            },
            &[String::new()],
            &logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        assert_eq!(res, Err(Error::ProgramIdNotFound));

        Ok(())
    }

    #[test]
    fn test_handle_compiled_instruction() -> Result<(), Error> {
        let logs = get_tx_1_logs();
        let accounts = get_tx_1_accounts();

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        Ok(())
    }

    #[test]
    fn test_handle_compiled_instruction_from_tx_1_full() -> Result<(), Error> {
        let logs = get_tx_1_logs();
        let accounts = get_tx_1_accounts();

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = rem_logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 9, // in this case let's set the correct index for the bankmen lending program
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &Pubkey::from_str("BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW").unwrap(),
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (16, 1));

        Ok(())
    }

    #[test]
    fn test_handle_compiled_instruction_from_tx_2_full() -> Result<(), Error> {
        let logs = get_tx_2_logs();
        let accounts = get_tx_1_accounts();

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = rem_logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 9, // in this case let's set the correct index for the bankmen lending program
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &Pubkey::from_str("BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW").unwrap(),
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (23, 1));

        let (_, rem_logs) = rem_logs.split_at(24);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 9, // in this case let's set the correct index for the bankmen lending program
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &Pubkey::from_str("BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW").unwrap(),
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (23, 1));

        Ok(())
    }

    #[test]
    fn test_handle_compiled_instruction_from_tx_3_full() -> Result<(), Error> {
        let logs = get_tx_3_logs();
        let accounts = get_tx_1_accounts();

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 10, // in this case let's set the correct index for the compute budget
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &anchor_lang::system_program::ID,
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (1, 0));

        let (_, rem_logs) = rem_logs.split_at(2);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 9, // in this case let's set the correct index for the bankmen lending program
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &Pubkey::from_str("BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW").unwrap(),
            &log_handler,
        );

        // in this case we are checking for system program logs, but the function returns after the first instruction logs
        // which is the compute budget program
        assert_eq!(res.unwrap(), (25, 3));

        let (_, rem_logs) = rem_logs.split_at(26);

        let res = handle_compiled_instruction(
            &mut None,
            &UiCompiledInstruction {
                program_id_index: 9, // in this case let's set the correct index for the bankmen lending program
                accounts: vec![], // this would be helpful to set if we were testing the log handler
                data: String::new(), // same goes for this, as this is the instruction data
                stack_height: Some(1),
            },
            &accounts,
            &rem_logs,
            &Pubkey::from_str("BMfi6hbCSpTS962EZjwaa6bRvy2izUCmZrpBMuhJ1BUW").unwrap(),
            &log_handler,
        );

        // the last instruction also has multiple inner events
        // we assert that the given log handler gets called 7 times
        assert_eq!(res.unwrap(), (29, 7));

        Ok(())
    }
}
