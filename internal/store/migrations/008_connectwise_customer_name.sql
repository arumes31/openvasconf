ALTER TABLE customers
    ADD COLUMN connectwise_customer_name TEXT NOT NULL DEFAULT '';

UPDATE customers
SET connectwise_customer_name = cid
WHERE connectwise_customer_name = '' AND cid <> '';

UPDATE hookwise_outbox
SET payload = json_remove(
    json_set(
        payload,
        '$.connectwise_customer_name',
        json_extract(payload, '$.cid')
    ),
    '$.cid'
)
WHERE json_valid(payload) AND json_type(payload, '$.cid') = 'text';

CREATE INDEX customers_connectwise_customer_name_idx
    ON customers(connectwise_customer_name COLLATE NOCASE);
