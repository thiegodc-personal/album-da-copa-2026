-- ============================================================================
-- Album Copa 2026 — sincronização online (schema isolado `album`)
-- Projeto Supabase PESSOAL evbsrhswkiahoqbadwcy (compartilhado com o app Bolão,
-- que vive em `public`). Este schema é 100% separado do Bolão.
--
-- Modelo de acesso: id legível + PIN de 4 dígitos, SEM Supabase Auth.
-- A tabela fica FECHADA por RLS (nenhuma policy permissiva). Todo acesso é via
-- RPCs SECURITY DEFINER que validam id+PIN. O app usa a anon key (role `anon`).
--
-- Lições aplicadas (memória do projeto Bolão, mesmo banco):
--   - GRANT EXECUTE p/ o role que chama (aqui: anon) nas RPCs.
--   - search_path fixo nas funções (anti-hijack).
--   - PIN guardado com hash bcrypt (pgcrypto crypt/gen_salt), nunca em texto puro.
-- Idempotente: pode rodar de novo sem quebrar.
-- ============================================================================

create schema if not exists album;

create extension if not exists pgcrypto;  -- crypt(), gen_salt() — já instalada no projeto

-- ----------------------------------------------------------------------------
-- Tabela única: uma linha por usuário (id legível escolhido pela pessoa).
-- ----------------------------------------------------------------------------
create table if not exists album.collections (
  user_id      text primary key
                 check (user_id ~ '^[a-z0-9._-]{3,30}$'),   -- id normalizado (minúsculo)
  pin_hash     text        not null,                         -- bcrypt do PIN (nunca o PIN)
  display_name text        not null default '',              -- nome de exibição (collectorName)
  state        jsonb       not null default '{}'::jsonb,     -- o state do app
  version      bigint      not null default 1,               -- contador anti-corrida
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

comment on table album.collections is
  'Tracker Panini Copa 2026: 1 linha por usuário (id+PIN). Acesso só via RPCs album_*.';

-- RLS LIGADO e SEM policy permissiva => tabela inacessível para anon/authenticated
-- por acesso direto. Só as funções SECURITY DEFINER (donas) conseguem ler/escrever.
alter table album.collections enable row level security;
alter table album.collections force row level security;

-- Garante que o role anon NÃO tem grants de tabela (defesa em profundidade;
-- mesmo que alguém tente ler direto via PostgREST, RLS + ausência de grant barram).
revoke all on album.collections from anon, authenticated;
-- O schema precisa ser "usável" para o PostgREST resolver as RPCs, mas sem
-- expor as tabelas (já barradas por RLS + revoke acima).
grant usage on schema album to anon, authenticated;

-- ----------------------------------------------------------------------------
-- Helper interno: merge de dois states do álbum.
-- Regras (decididas com o usuário): "mesclar tudo, nunca perder marcação".
--   collected{}  -> UNIÃO  (marcado em qualquer lado = marcado)
--   duplicates{} -> MAX por figurinha (mais repetidas vence)
--   teamOrder{}  -> o do INCOMING (cliente) vence (preferência de quem salvou)
--   collectorName/repeatHelpShown -> incoming vence se preenchido
-- Idempotente e comutativa o suficiente p/ o uso (união + max).
-- ----------------------------------------------------------------------------
create or replace function album._merge_state(p_base jsonb, p_incoming jsonb)
returns jsonb
language plpgsql
immutable
set search_path = album, public, pg_temp
as $$
declare
  v_base     jsonb := coalesce(p_base, '{}'::jsonb);
  v_incoming jsonb := coalesce(p_incoming, '{}'::jsonb);
  v_collected jsonb;
  v_duplicates jsonb := '{}'::jsonb;
  v_key text;
  v_base_dups jsonb := coalesce(v_base->'duplicates', '{}'::jsonb);
  v_inc_dups  jsonb := coalesce(v_incoming->'duplicates', '{}'::jsonb);
  v_bn numeric;
  v_in numeric;
begin
  -- collected: união (true vence). concatenar incoming sobre base já basta porque
  -- só guardamos chaves true; mas para não perder marcações antigas, unimos os dois.
  v_collected := coalesce(v_base->'collected', '{}'::jsonb) || coalesce(v_incoming->'collected', '{}'::jsonb);

  -- duplicates: max por chave entre base e incoming
  for v_key in
    select jsonb_object_keys(v_base_dups)
    union
    select jsonb_object_keys(v_inc_dups)
  loop
    v_bn := coalesce((v_base_dups->>v_key)::numeric, 0);
    v_in := coalesce((v_inc_dups ->>v_key)::numeric, 0);
    v_duplicates := v_duplicates || jsonb_build_object(v_key, greatest(v_bn, v_in));
  end loop;

  -- monta o resultado: começa do incoming (preserva teamOrder, flags do cliente),
  -- e sobrescreve collected/duplicates com os mesclados.
  return v_incoming
    || jsonb_build_object('collected', v_collected)
    || jsonb_build_object('duplicates', v_duplicates);
end;
$$;

-- ----------------------------------------------------------------------------
-- RPC: checar se um id está livre (UX do cadastro). Não expõe dados.
-- ----------------------------------------------------------------------------
create or replace function album.album_check_id(p_user_id text)
returns boolean                      -- true = LIVRE (pode usar)
language sql
security definer
stable
set search_path = album, public, pg_temp
as $$
  select not exists (
    select 1 from album.collections where user_id = lower(trim(p_user_id))
  );
$$;

-- ----------------------------------------------------------------------------
-- RPC: cadastro. Cria a conta com id+PIN e o state inicial (migração do local).
-- Erros: id inválido, PIN inválido, id já existe.
-- ----------------------------------------------------------------------------
create or replace function album.album_signup(
  p_user_id      text,
  p_pin          text,
  p_display_name text,
  p_state        jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare
  v_id  text := lower(trim(p_user_id));
  v_row album.collections;
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
-- RPC: login. Valida id+PIN e devolve o state. Mensagem genérica (não revela
-- se o id existe) para não virar oráculo de ids.
-- ----------------------------------------------------------------------------
create or replace function album.album_login(p_user_id text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare
  v_id  text := lower(trim(p_user_id));
  v_row album.collections;
begin
  select * into v_row from album.collections where user_id = v_id;
  if not found or v_row.pin_hash <> crypt(p_pin, v_row.pin_hash) then
    return jsonb_build_object('ok', false, 'error', 'credenciais',
      'message', 'id ou PIN incorretos.');
  end if;
  return jsonb_build_object('ok', true, 'user_id', v_row.user_id,
    'display_name', v_row.display_name, 'state', v_row.state, 'version', v_row.version);
end;
$$;

-- ----------------------------------------------------------------------------
-- RPC: save. Valida id+PIN, MESCLA o state recebido com o do banco (rede de
-- segurança contra sobrescrita), grava, incrementa version. Devolve o mesclado.
-- ----------------------------------------------------------------------------
create or replace function album.album_save(p_user_id text, p_pin text, p_state jsonb)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare
  v_id     text := lower(trim(p_user_id));
  v_row    album.collections;
  v_merged jsonb;
begin
  select * into v_row from album.collections where user_id = v_id;
  if not found or v_row.pin_hash <> crypt(p_pin, v_row.pin_hash) then
    return jsonb_build_object('ok', false, 'error', 'credenciais',
      'message', 'id ou PIN incorretos.');
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
-- RPC ADMIN: resetar PIN (só você, via SQL/Management API — NÃO exposta ao app).
-- Uso: select album.album_admin_reset_pin('thiego', '1234');
-- Não tem GRANT para anon/authenticated; só roda com service_role/owner.
-- ----------------------------------------------------------------------------
create or replace function album.album_admin_reset_pin(p_user_id text, p_new_pin text)
returns jsonb
language plpgsql
security definer
set search_path = album, public, extensions, pg_temp
as $$
declare
  v_id text := lower(trim(p_user_id));
  v_n  bigint;
begin
  if p_new_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('ok', false, 'error', 'pin_invalido');
  end if;
  update album.collections set pin_hash = crypt(p_new_pin, gen_salt('bf')), updated_at = now()
   where user_id = v_id;
  get diagnostics v_n = row_count;
  return jsonb_build_object('ok', v_n > 0, 'user_id', v_id,
    'message', case when v_n > 0 then 'PIN redefinido.' else 'id não encontrado.' end);
end;
$$;

-- ----------------------------------------------------------------------------
-- GRANTS: o app (anon key => role anon) só pode chamar estas 4 RPCs.
-- Tira o EXECUTE de PUBLIC primeiro (vem por padrão), depois concede só ao anon.
-- A função de admin e o helper de merge NÃO recebem grant (ficam internos).
-- ----------------------------------------------------------------------------
revoke all on function album.album_check_id(text)             from public;
revoke all on function album.album_signup(text,text,text,jsonb) from public;
revoke all on function album.album_login(text,text)           from public;
revoke all on function album.album_save(text,text,jsonb)      from public;
revoke all on function album._merge_state(jsonb,jsonb)        from public;
revoke all on function album.album_admin_reset_pin(text,text) from public;

grant execute on function album.album_check_id(text)             to anon, authenticated;
grant execute on function album.album_signup(text,text,text,jsonb) to anon, authenticated;
grant execute on function album.album_login(text,text)           to anon, authenticated;
grant execute on function album.album_save(text,text,jsonb)      to anon, authenticated;

-- ----------------------------------------------------------------------------
-- Trigger p/ manter updated_at coerente em updates diretos (defesa extra).
-- ----------------------------------------------------------------------------
create or replace function album._touch_updated_at()
returns trigger language plpgsql set search_path = album, pg_temp as $$
begin new.updated_at := now(); return new; end; $$;

revoke all on function album._touch_updated_at() from public, anon, authenticated;

drop trigger if exists trg_touch_updated_at on album.collections;
create trigger trg_touch_updated_at before update on album.collections
  for each row execute function album._touch_updated_at();
