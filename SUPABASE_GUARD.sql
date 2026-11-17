-- ============================================================
-- 圣诞树 · 祝福防护（完整版）
-- 一条龙：敏感词表 + IP 限流 + 清理上一轮测试垃圾数据
-- 用法：Supabase → SQL Editor → New query → 全选粘贴 → Run
-- 可重复运行，不会重复建表 / 不会重复插词
-- ============================================================

-- ------------------------------------------------------------
-- 0. 清掉我上一轮测试时写进去的垃圾数据
--    只按内容精确匹配，不会碰到任何真实祝福
-- ------------------------------------------------------------
delete from public.wishes
 where content = '圣诞快乐，万事胜意'
    or content like '限流测试第%';


-- ------------------------------------------------------------
-- 1. 敏感词表（以后改词库直接改这张表，不用动触发器）
-- ------------------------------------------------------------
create table if not exists public.wish_banned_words (
  word text primary key
);

alter table public.wish_banned_words enable row level security;
revoke all on public.wish_banned_words from anon;

insert into public.wish_banned_words (word) values
  ('傻逼'), ('妈的'), ('操你'), ('去死'), ('婊子'),
  ('fuck'), ('shit'), ('bitch'),
  ('加微信'), ('代购'), ('刷单'), ('返利'), ('贷款'), ('博彩')
on conflict (word) do nothing;


-- ------------------------------------------------------------
-- 2. 限流表（你之前已建过，这里补索引和 RLS，可重复执行）
-- ------------------------------------------------------------
create table if not exists public.wish_rate (
  ip text,
  ts timestamptz default now()
);

create index if not exists wish_rate_ip_ts_idx
  on public.wish_rate (ip, ts desc);

alter table public.wish_rate enable row level security;
revoke all on public.wish_rate from anon;


-- ------------------------------------------------------------
-- 3. 校验触发器函数
--    沿用你已有的函数名 check_wish_content，直接覆盖升级
--    security definer：以表所有者身份执行，才能读写上面两张内部表
-- ------------------------------------------------------------
create or replace function public.check_wish_content()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  bad              text;
  client_ip        text;
  recent           int;
  window_minutes   constant int := 10;   -- 时间窗：10 分钟
  max_per_window   constant int := 3;    -- 同一 IP 最多 3 条
begin
  -- 长度兜底：前端截断能被绕过，这里才是硬约束
  new.content := btrim(new.content);
  if char_length(new.content) < 1 or char_length(new.content) > 40 then
    raise exception '心愿要在 1~40 字之间';
  end if;

  -- 敏感词（表驱动，改词不用动函数）
  select w.word into bad
    from public.wish_banned_words w
   where char_length(w.word) > 0
     and position(lower(w.word) in lower(new.content)) > 0
   limit 1;

  if bad is not null then
    raise exception '内容包含敏感词';
  end if;

  -- 取客户端 IP：PostgREST 把请求头塞进 request.headers 这个 GUC
  begin
    client_ip := btrim(split_part(
      coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''),
      ',', 1));
  exception when others then
    client_ip := '';
  end;

  -- 取不到 IP 就跳过限流（宁可漏挡，也不要把所有人都误判成同一个 IP）
  if client_ip <> '' then
    select count(*) into recent
      from public.wish_rate
     where ip = client_ip
       and ts > now() - (window_minutes || ' minutes')::interval;

    if recent >= max_per_window then
      raise exception '心愿有点密集，歇 % 分钟再来吧', window_minutes;
    end if;

    insert into public.wish_rate (ip) values (client_ip);

    -- 2% 概率顺手清掉 24 小时前的旧记录，省得表无限膨胀
    if random() < 0.02 then
      delete from public.wish_rate where ts < now() - interval '24 hours';
    end if;
  end if;

  return new;
end;
$$;


-- ------------------------------------------------------------
-- 4. 重建触发器（原来那个叫 wishes_filter，沿用，重新挂一次）
-- ------------------------------------------------------------
drop trigger if exists wishes_filter on public.wishes;
create trigger wishes_filter
  before insert on public.wishes
  for each row execute function public.check_wish_content();


-- ------------------------------------------------------------
-- 5. 临时诊断函数：让我能从外网验证「IP 到底取没取到」
--    验证完可以执行最后那行 drop 删掉
-- ------------------------------------------------------------
create or replace function public.whoami_ip()
returns text
language sql
security definer
set search_path = public
as $$
  select coalesce(
    current_setting('request.headers', true)::json ->> 'x-forwarded-for',
    '(none)'
  )
$$;

grant execute on function public.whoami_ip() to anon;


-- ------------------------------------------------------------
-- 6. 自检
-- ------------------------------------------------------------
select (select count(*) from public.wish_banned_words) as banned_words,
       (select count(*) from public.wishes)             as wishes,
       (select count(*) from public.wish_rate)          as rate_rows;

-- 全部验证通过后，可执行下面这行删掉诊断函数
-- drop function if exists public.whoami_ip();
