use crate::schema::signature_checkpoint;
use chrono::NaiveDateTime;
use diesel::{Identifiable, Insertable, Queryable, Selectable};

#[derive(Queryable, Selectable, Identifiable, Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = signature_checkpoint)]
#[diesel(primary_key(signature))]
pub struct Checkpoint {
    #[diesel(sql_type = Text)]
    pub signature: String,
    #[diesel(sql_type = Timestamptz)]
    pub created_at: NaiveDateTime,
    #[diesel(sql_type = Timestamptz)]
    pub updated_at: NaiveDateTime,
}
