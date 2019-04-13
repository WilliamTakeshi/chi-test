CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


create table teachers (
    id SERIAL PRIMARY KEY,
    username varchar (127) UNIQUE NOT NULL,
    full_name varchar(255) NOT NULL,
    email varchar(255) NOT NULL,
    password_hash varchar (255) NOT NULL,
    is_disabled bool DEFAULT true NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON teachers
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();