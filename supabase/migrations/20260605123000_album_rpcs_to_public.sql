-- ============================================================================
-- Ajuste: o PostgREST do Supabase só expõe os schemas `public` e `graphql_public`.
-- Expor o schema `album` exigiria mudar a config da API do PROJETO INTEIRO
-- (compartilhado com o app Bolão). Em vez disso, movemos só as RPCs para
-- `public` (com nome prefixado `album_*`); a TABELA `album.collections`
-- continua isolada em `album` e fechada (RLS + sem grant a anon).
--
-- Resultado: o app chama public.album_* (expostas à API REST). A tabela
-- permanece inacessível por acesso direto. Isolamento de dados preservado.
-- Idempotente.
-- ============================================================================

-- Remove as versões antigas que ficaram no schema `album` (não eram acessíveis
-- via REST de qualquer forma). O helper _merge_state PERMANECE em `album`.
drop function if exists album.album_check_id(text);
drop function if exists album.album_signup(text,text,text,jsonb);
drop function if exists album.album_login(text,text);
drop function if exists album.album_save(text,text,jsonb);
drop function if exists album.album_admin_reset_pin(text,text);

-- ----------------------------------------------------------------------------
-- public.album_check_id — id está livre? (não expõe dados)
-- ----------------------------------------------------------------------------
create or replace function public.album_check_id(p_user_id text)
returns boolean
language sql
security definer
stable
set search_path = album, public, extensions, pg_temp
as $$
  select not exists (select 1 from album.collections where user_id = lower(trim(p_user_id)));
$$;

-- ----------------------------------------------------------------------------
-- public.album_signup
-- ----------------------------------------------------------------------------
create or replace function public.album_signup(
  p_user_id text, p_pin text, p_display_name text, p_state jsonb
) returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare v_id text := lower(trim(p_user_id)); v_row album.collections;
begin
  if v_id !~ '^[a-z0-9._-]{3,30}$' then
    return jsonb_build_object('ok', false, 'error', 'id_invalido',
      'message', 'O id deve ter 3 a 30 caracteres (letras, números, ponto, hífen ou _).');
  end if;
  if p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('ok', false, 'error', 'pin_invalido',
      'message', 'O PIN deve ter exatamente 4 dígitos.');
  end if;
  begin
    insert into album.collections (user_id, pin_hash, display_name, state, version)
    values (v_id, crypt(p_pin, gen_salt('bf')), coalesce(p_display_name, ''),
            coalesce(p_state, '{}'::jsonb), 1)
    returning * into v_row;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'error', 'id_em_uso',
      'message', 'Esse id já está em uso. Escolha outro.');
  end;
  return jsonb_build_object('ok', true, 'user_id', v_row.user_id,
    'display_name', v_row.display_name, 'state', v_row.state, 'version', v_row.version);
end;
$$;

-- ----------------------------------------------------------------------------
-- public.album_login
-- ----------------------------------------------------------------------------
create or replace function public.album_login(p_user_id text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare v_id text := lower(trim(p_user_id)); v_row album.collections;
begin
  select * into v_row from album.collections where user_id = v_id;
  if not found or v_row.pin_hash <> crypt(p_pin, v_row.pin_hash) then
    return jsonb_build_object('ok', false, 'error', 'credenciais', 'message', 'id ou PIN incorretos.');
  end if;
  return jsonb_build_object('ok', true, 'user_id', v_row.user_id,
    'display_name', v_row.display_name, 'state', v_row.state, 'version', v_row.version);
end;
$$;

-- ----------------------------------------------------------------------------
-- public.album_save — valida id+PIN, MESCLA, grava, incrementa version
-- ----------------------------------------------------------------------------
create or replace function public.album_save(p_user_id text, p_pin text, p_state jsonb)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare v_id text := lower(trim(p_user_id)); v_row album.collections; v_merged jsonb;
begin
  select * into v_row from album.collections where user_id = v_id;
  if not found or v_row.pin_hash <> crypt(p_pin, v_row.pin_hash) then
    return jsonb_build_object('ok', false, 'error', 'credenciais', 'message', 'id ou PIN incorretos.');
  end if;
  v_merged := album._merge_state(v_row.state, coalesce(p_state, '{}'::jsonb));
  update album.collections
     set state = v_merged,
         display_name = coalesce(nullif(p_state->>'collectorName', ''), display_name),
         version = version + 1,
         updated_at = now()
   where user_id = v_id
   returning * into v_row;
  return jsonb_build_object('ok', true, 'user_id', v_row.user_id,
    'display_name', v_row.display_name, 'state', v_row.state, 'version', v_row.version);
end;
$$;

-- ----------------------------------------------------------------------------
-- public.album_admin_reset_pin — só você (via PAT). Sem grant a anon.
-- ----------------------------------------------------------------------------
create or replace function public.album_admin_reset_pin(p_user_id text, p_new_pin text)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare v_id text := lower(trim(p_user_id)); v_n bigint;
begin
  if p_new_pin !~ '^[0-9]{4}$' then return jsonb_build_object('ok', false, 'error', 'pin_invalido'); end if;
  update album.collections set pin_hash = crypt(p_new_pin, gen_salt('bf')), updated_at = now() where user_id = v_id;
  get diagnostics v_n = row_count;
  return jsonb_build_object('ok', v_n > 0, 'user_id', v_id,
    'message', case when v_n > 0 then 'PIN redefinido.' else 'id não encontrado.' end);
end;
$$;

-- ----------------------------------------------------------------------------
-- GRANTS: tira de PUBLIC, concede só as 4 RPCs do app ao anon.
-- admin_reset_pin NÃO recebe grant (interno/PAT).
-- ----------------------------------------------------------------------------
revoke all on function public.album_check_id(text)               from public;
revoke all on function public.album_signup(text,text,text,jsonb) from public;
revoke all on function public.album_login(text,text)             from public;
revoke all on function public.album_save(text,text,jsonb)        from public;
revoke all on function public.album_admin_reset_pin(text,text)   from public;

grant execute on function public.album_check_id(text)               to anon, authenticated;
grant execute on function public.album_signup(text,text,text,jsonb) to anon, authenticated;
grant execute on function public.album_login(text,text)             to anon, authenticated;
grant execute on function public.album_save(text,text,jsonb)        to anon, authenticated;
