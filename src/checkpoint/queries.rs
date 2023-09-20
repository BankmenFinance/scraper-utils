use super::model::Checkpoint;
use crate::schema::signature_checkpoint::dsl::*;
use diesel::{PgConnection, QueryDsl, QueryResult, RunQueryDsl};

pub fn get_checkpoint(connection: &mut PgConnection) -> QueryResult<Vec<Checkpoint>> {
    signature_checkpoint::select(signature_checkpoint, (signature, created_at, updated_at))
        .load::<Checkpoint>(connection)
}
