diesel::table! {
    signatures (signature) {
        signature -> Text,
        slot -> Int8,
        created_at -> Timestamptz,
        block_time -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        error -> Nullable<Text>,
    }
}

diesel::table! {
    signature_checkpoint (signature) {
        signature -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(signature_checkpoint, signatures,);
