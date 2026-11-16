-- Internal storage metadata only. Application tables are added as their contracts
-- are implemented; this migration does not imply OpenBot API compatibility.
CREATE TABLE port_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
