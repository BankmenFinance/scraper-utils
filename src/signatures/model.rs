use crate::schema::signatures;
use chrono::NaiveDateTime;
use diesel::{Identifiable, Insertable, Queryable, Selectable};

#[derive(Queryable, Selectable, Identifiable, Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = signatures)]
#[diesel(primary_key(signature))]
pub struct Signature {
    #[diesel(sql_type = Text)]
    pub signature: String,
    #[diesel(sql_type = Int8)]
    pub slot: i64,
    #[diesel(sql_type = Timestamptz)]
    pub created_at: NaiveDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub block_time: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    pub updated_at: Option<NaiveDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    pub error: Option<String>,
}
