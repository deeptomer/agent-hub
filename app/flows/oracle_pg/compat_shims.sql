-- Oracle compatibility shims for PostgreSQL (installed into the migration sandbox, and recommended for the target).
-- Each function reproduces Oracle behaviour that PostgreSQL has no direct built-in for.

CREATE OR REPLACE FUNCTION add_months(d timestamp, n integer) RETURNS timestamp
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN d::date = (date_trunc('month', d) + interval '1 month' - interval '1 day')::date
      THEN (date_trunc('month', d + make_interval(months => n)) + interval '1 month' - interval '1 day')
           + (d - date_trunc('day', d))
    ELSE d + make_interval(months => n)
  END
$$;

CREATE OR REPLACE FUNCTION months_between(d1 timestamp, d2 timestamp) RETURNS numeric
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN extract(day from d1) = extract(day from d2)
      OR (d1::date = (date_trunc('month', d1) + interval '1 month' - interval '1 day')::date
          AND d2::date = (date_trunc('month', d2) + interval '1 month' - interval '1 day')::date)
      THEN ((extract(year from d1) - extract(year from d2)) * 12
            + (extract(month from d1) - extract(month from d2)))::numeric
    ELSE ((extract(year from d1) - extract(year from d2)) * 12
          + (extract(month from d1) - extract(month from d2))
          + (extract(day from d1) - extract(day from d2)
             + (extract(epoch from d1::time) - extract(epoch from d2::time)) / 86400.0) / 31.0)::numeric
  END
$$;

CREATE OR REPLACE FUNCTION last_day(d timestamp) RETURNS timestamp
LANGUAGE sql IMMUTABLE AS $$
  SELECT (date_trunc('month', d) + interval '1 month' - interval '1 day') + (d - date_trunc('day', d))
$$;

CREATE OR REPLACE FUNCTION instr(str text, sub text, pos integer DEFAULT 1, occurrence integer DEFAULT 1)
RETURNS integer LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  found integer := 0;
  idx integer;
  cur integer := pos;
BEGIN
  IF str IS NULL OR sub IS NULL THEN RETURN NULL; END IF;
  FOR i IN 1..occurrence LOOP
    idx := strpos(substr(str, cur), sub);
    IF idx = 0 THEN RETURN 0; END IF;
    found := cur + idx - 1;
    cur := found + 1;
  END LOOP;
  RETURN found;
END
$$;

CREATE OR REPLACE FUNCTION regexp_like(str text, pattern text, flags text DEFAULT '') RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN position('i' in flags) > 0 THEN str ~* pattern ELSE str ~ pattern END
$$;

CREATE OR REPLACE FUNCTION to_number(str text) RETURNS numeric
LANGUAGE sql IMMUTABLE AS $$ SELECT str::numeric $$;

CREATE OR REPLACE FUNCTION to_char(n numeric) RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT n::text $$;

CREATE OR REPLACE FUNCTION sys_guid() RETURNS text
LANGUAGE sql VOLATILE AS $$ SELECT upper(replace(gen_random_uuid()::text, '-', '')) $$;
