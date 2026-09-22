-- The origin is read on every non-health request (through a five-second
-- cache). Nothing in the serving path writes a setting: `set-origin` and
-- `bootstrap` are CLI-only, under the maintenance role. Hence SELECT alone.
GRANT SELECT ON TABLE public.app_settings TO {grant_to}
