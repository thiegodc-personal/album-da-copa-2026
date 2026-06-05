-- ============================================================================
-- Troca da estratégia de merge: de "mesclar tudo" (união/max) para
-- LWW = última edição vence POR FIGURINHA, via mapa clocks[id]=epoch_ms.
--
-- Motivo: união nunca perde uma marcação, mas torna a DESMARCAÇÃO impossível
-- de propagar (o lado que ainda tinha marcado "ressuscitava" a figurinha).
-- Agora cada figurinha carrega o instante da última alteração; no merge, o
-- lado com clock maior define marcação E repetidas daquela figurinha.
--
-- Mantém a assinatura album._merge_state(base, incoming) → o album_save não muda.
-- Idempotente (create or replace).
-- ============================================================================

create or replace function album._merge_state(p_base jsonb, p_incoming jsonb)
returns jsonb
language plpgsql
immutable
set search_path = album, public, pg_temp
as $$
declare
  v_base     jsonb := coalesce(p_base, '{}'::jsonb);
  v_incoming jsonb := coalesce(p_incoming, '{}'::jsonb);
  v_b_col jsonb := coalesce(v_base->'collected',  '{}'::jsonb);
  v_b_dup jsonb := coalesce(v_base->'duplicates', '{}'::jsonb);
  v_b_clk jsonb := coalesce(v_base->'clocks',     '{}'::jsonb);
  v_i_col jsonb := coalesce(v_incoming->'collected',  '{}'::jsonb);
  v_i_dup jsonb := coalesce(v_incoming->'duplicates', '{}'::jsonb);
  v_i_clk jsonb := coalesce(v_incoming->'clocks',     '{}'::jsonb);
  v_out_col jsonb := '{}'::jsonb;
  v_out_dup jsonb := '{}'::jsonb;
  v_out_clk jsonb := '{}'::jsonb;
  v_id  text;
  v_bc  numeric;  -- base clock
  v_ic  numeric;  -- incoming clock
  v_win text;     -- lado vencedor: 'b' ou 'i'
  v_has boolean;
  v_dup numeric;
begin
  -- universo de ids: chaves de clocks/collected/duplicates dos dois lados
  for v_id in
    select k from (
      select jsonb_object_keys(v_b_clk) k union
      select jsonb_object_keys(v_i_clk)   union
      select jsonb_object_keys(v_b_col)   union
      select jsonb_object_keys(v_i_col)   union
      select jsonb_object_keys(v_b_dup)   union
      select jsonb_object_keys(v_i_dup)
    ) s
  loop
    v_bc := coalesce((v_b_clk->>v_id)::numeric, 0);
    v_ic := coalesce((v_i_clk->>v_id)::numeric, 0);
    -- empate ou base maior → base vence (estável); incoming só vence se clock estritamente maior
    v_win := case when v_ic > v_bc then 'i' else 'b' end;

    if v_win = 'i' then
      v_has := coalesce((v_i_col->>v_id)::boolean, false);
      v_dup := case when v_has then coalesce((v_i_dup->>v_id)::numeric, 0) else 0 end;
    else
      v_has := coalesce((v_b_col->>v_id)::boolean, false);
      v_dup := case when v_has then coalesce((v_b_dup->>v_id)::numeric, 0) else 0 end;
    end if;

    if v_has then
      v_out_col := v_out_col || jsonb_build_object(v_id, true);
      if v_dup > 0 then v_out_dup := v_out_dup || jsonb_build_object(v_id, v_dup); end if;
    end if;
    -- clock resultante = o maior dos dois (preserva a fronteira temporal)
    v_out_clk := v_out_clk || jsonb_build_object(v_id, greatest(v_bc, v_ic));
  end loop;

  -- teamOrder: incoming vence se vier; senão base. Nome/flag: incoming se preenchido.
  return (case when v_incoming ? 'teamOrder' then v_incoming else v_base end)
    || jsonb_build_object('collected',  v_out_col)
    || jsonb_build_object('duplicates', v_out_dup)
    || jsonb_build_object('clocks',     v_out_clk)
    || jsonb_build_object('collectorName',
         coalesce(nullif(v_incoming->>'collectorName',''), v_base->>'collectorName', ''));
end;
$$;

-- _merge_state continua interno (sem grant a anon).
revoke all on function album._merge_state(jsonb,jsonb) from public;
