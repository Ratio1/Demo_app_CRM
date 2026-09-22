-- Postcondition for 21_app_settings: four columns, `updated_by_user_id` the
-- only nullable one (DATA_CONTRACT.md §7.3).
SELECT (
      (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'app_settings'
          AND column_name IN ('key','value','updated_at','updated_by_user_id')) = 4
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'app_settings') = 4
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'app_settings'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'app_settings'
          AND column_name = 'updated_by_user_id' AND is_nullable = 'YES') = 1
) AS ok
