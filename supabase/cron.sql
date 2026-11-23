-- Schedules for the assistant. The signing key stays in Supabase Vault as `sweep_secret`.
create extension if not exists pg_cron;
create extension if not exists pg_net;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists assistant;
revoke all on schema assistant from public;

create or replace function assistant.call(task text) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  payload jsonb := to_jsonb(task || ' ' || extract(epoch from now())::bigint);
  key text;
begin
  select decrypted_secret into strict key from vault.decrypted_secrets where name = 'sweep_secret';
  return net.http_post(
    url := 'https://fcgpbbglbgnzrednkcay.supabase.co/functions/v1/pr-assistant/sweep',
    body := payload,
    headers := jsonb_build_object(
      'content-type', 'application/json',
      'x-sweep-signature', 'sha256=' || encode(
        extensions.hmac(convert_to(payload::text, 'utf8'), convert_to(key, 'utf8'), 'sha256'), 'hex')
    )
  );
end $$;
revoke all on function assistant.call(text) from public;

select cron.schedule('assistant-sweep', '*/10 * * * *', $$select assistant.call('sweep')$$);
select cron.schedule('assistant-hourly', '41 * * * *', $$select assistant.call('hourly')$$);
select cron.schedule('assistant-daily', '23 8 * * *', $$select assistant.call('daily')$$);
