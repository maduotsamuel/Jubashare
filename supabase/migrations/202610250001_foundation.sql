-- JAMB TOOLS RENTAL: initial secure workflow schema
create extension if not exists pgcrypto;
create table public.profiles(id uuid primary key references auth.users(id) on delete cascade,full_name text not null default '',created_at timestamptz not null default now());
create table public.user_roles(user_id uuid not null references auth.users(id) on delete cascade,role text not null check(role in ('customer','owner','admin','super_admin')),primary key(user_id,role));
create table public.owner_profiles(user_id uuid primary key references auth.users(id) on delete cascade,business_name text not null check(length(trim(business_name))>=2),verified boolean not null default false,created_at timestamptz not null default now());
create table public.categories(id uuid primary key default gen_random_uuid(),name text not null unique);
create table public.equipment_listings(id uuid primary key default gen_random_uuid(),owner_id uuid not null references public.owner_profiles(user_id),category_id uuid not null references public.categories(id),title text not null check(length(trim(title)) between 3 and 130),description text not null default '',brand text,model text,city text not null default 'Juba',condition text not null default 'good' check(condition in ('new','good','fair')),daily_rate bigint not null check(daily_rate>0),deposit_amount bigint not null default 0 check(deposit_amount>=0),quantity integer not null default 1 check(quantity between 1 and 10000),image_url text,status text not null default 'pending' check(status in ('pending','published','rejected','suspended')),created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create index equipment_catalog on public.equipment_listings(status,created_at desc);
create index equipment_owner on public.equipment_listings(owner_id);
create table public.bookings(id uuid primary key default gen_random_uuid(),reference text not null unique default ('JTR-'||upper(encode(gen_random_bytes(5),'hex'))),listing_id uuid not null references public.equipment_listings(id),customer_id uuid not null references auth.users(id),owner_id uuid not null references auth.users(id),start_at timestamptz not null,end_at timestamptz not null,quantity integer not null check(quantity>0),quoted_subtotal bigint not null check(quoted_subtotal>=0),quoted_deposit bigint not null check(quoted_deposit>=0),quoted_total bigint not null check(quoted_total>=0),status text not null default 'awaiting_approval' check(status in ('awaiting_approval','awaiting_payment','confirmed','active','return_pending','completed','cancelled','rejected','expired','disputed')),payment_status text not null default 'unpaid' check(payment_status in ('unpaid','verification_pending','verified','refunded')),created_at timestamptz not null default now(),updated_at timestamptz not null default now(),constraint valid_rental_period check(end_at>start_at));
create index booking_conflict on public.bookings(listing_id,start_at,end_at,status);
create index booking_customer on public.bookings(customer_id,created_at desc);
create index booking_owner on public.bookings(owner_id,created_at desc);
create table public.booking_status_history(id bigint generated always as identity primary key,booking_id uuid not null references public.bookings(id),old_status text,new_status text not null,changed_by uuid references auth.users(id),changed_at timestamptz not null default now());
create table public.audit_logs(id bigint generated always as identity primary key,actor_id uuid,action text not null,resource_type text not null,resource_id uuid,created_at timestamptz not null default now());
create table public.payment_evidence(id uuid primary key default gen_random_uuid(),booking_id uuid not null references public.bookings(id),submitted_by uuid not null references auth.users(id),channel text not null check(channel in ('cash','mobile_money','bank_transfer')),external_reference text,amount bigint not null check(amount>0),status text not null default 'pending' check(status in ('pending','verified','rejected')),verified_by uuid references auth.users(id),created_at timestamptz not null default now());
create table public.rental_inspections(id uuid primary key default gen_random_uuid(),booking_id uuid not null references public.bookings(id),inspection_type text not null check(inspection_type in ('handover','return')),notes text not null,recorded_by uuid not null references auth.users(id),created_at timestamptz not null default now(),unique(booking_id,inspection_type));

create or replace function public.is_admin() returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.user_roles where user_id=(select auth.uid()) and role in ('admin','super_admin'))$$;
revoke all on function public.is_admin() from public;grant execute on function public.is_admin() to authenticated;
create or replace function public.on_signup() returns trigger language plpgsql security definer set search_path='' as $$begin insert into public.profiles(id,full_name) values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''));insert into public.user_roles(user_id,role) values(new.id,'customer');return new;end$$;
create trigger create_profile after insert on auth.users for each row execute procedure public.on_signup();
create or replace function public.owner_registered() returns trigger language plpgsql security definer set search_path='' as $$begin insert into public.user_roles(user_id,role) values(new.user_id,'owner') on conflict do nothing;return new;end$$;
create trigger owner_role after insert on public.owner_profiles for each row execute function public.owner_registered();
create or replace function public.listing_guard() returns trigger language plpgsql set search_path='' as $$begin if tg_op='INSERT' then new.status:='pending';elsif (new.status is distinct from old.status or new.owner_id is distinct from old.owner_id) and not public.is_admin() then raise exception 'Only platform administrators can change listing status or owner';end if;new.updated_at:=now();return new;end$$;
create trigger protect_listing before insert or update on public.equipment_listings for each row execute function public.listing_guard();
create or replace function public.owner_profile_guard() returns trigger language plpgsql set search_path='' as $$begin if new.user_id is distinct from old.user_id or (new.verified is distinct from old.verified and not public.is_admin()) then raise exception 'Cannot change owner identity or verification';end if;return new;end$$;
create trigger protect_owner before update on public.owner_profiles for each row execute function public.owner_profile_guard();

alter table public.profiles enable row level security;
alter table public.user_roles enable row level security;
alter table public.owner_profiles enable row level security;
alter table public.categories enable row level security;
alter table public.equipment_listings enable row level security;
alter table public.bookings enable row level security;
alter table public.booking_status_history enable row level security;
alter table public.audit_logs enable row level security;
alter table public.payment_evidence enable row level security;
alter table public.rental_inspections enable row level security;
create policy self_profile_read on public.profiles for select to authenticated using(id=(select auth.uid()) or public.is_admin());
create policy self_profile_update on public.profiles for update to authenticated using(id=(select auth.uid())) with check(id=(select auth.uid()));
create policy role_self_read on public.user_roles for select to authenticated using(user_id=(select auth.uid()) or public.is_admin());
create policy owner_public_read on public.owner_profiles for select to anon,authenticated using(verified or user_id=(select auth.uid()) or public.is_admin());
create policy owner_self_create on public.owner_profiles for insert to authenticated with check(user_id=(select auth.uid()) and verified=false);
create policy owner_self_edit on public.owner_profiles for update to authenticated using(user_id=(select auth.uid())) with check(user_id=(select auth.uid()));
create policy category_public on public.categories for select to anon,authenticated using(true);
create policy listing_visible on public.equipment_listings for select to anon,authenticated using(status='published' or owner_id=(select auth.uid()) or public.is_admin());
create policy listing_create on public.equipment_listings for insert to authenticated with check(owner_id=(select auth.uid()) and status='pending');
create policy listing_update on public.equipment_listings for update to authenticated using(owner_id=(select auth.uid())) with check(owner_id=(select auth.uid()));
create policy booking_visible on public.bookings for select to authenticated using(customer_id=(select auth.uid()) or owner_id=(select auth.uid()) or public.is_admin());
create policy booking_history_visible on public.booking_status_history for select to authenticated using(exists(select 1 from public.bookings b where b.id=booking_id and (b.customer_id=(select auth.uid()) or b.owner_id=(select auth.uid()) or public.is_admin())));
create policy audit_admin_read on public.audit_logs for select to authenticated using(public.is_admin());
create policy evidence_visible on public.payment_evidence for select to authenticated using(submitted_by=(select auth.uid()) or public.is_admin() or exists(select 1 from public.bookings b where b.id=booking_id and b.owner_id=(select auth.uid())));
create policy inspection_visible on public.rental_inspections for select to authenticated using(exists(select 1 from public.bookings b where b.id=booking_id and (b.customer_id=(select auth.uid()) or b.owner_id=(select auth.uid()) or public.is_admin())));
revoke all on all tables in schema public from anon,authenticated;
grant select on public.categories,public.owner_profiles,public.equipment_listings to anon;
grant select on public.profiles,public.user_roles,public.owner_profiles,public.categories,public.equipment_listings,public.bookings,public.booking_status_history,public.audit_logs,public.payment_evidence,public.rental_inspections to authenticated;
grant update(full_name) on public.profiles to authenticated;
grant insert(user_id,business_name) on public.owner_profiles to authenticated;
grant update(business_name) on public.owner_profiles to authenticated;
grant insert(owner_id,category_id,title,description,brand,model,city,condition,daily_rate,deposit_amount,quantity,image_url) on public.equipment_listings to authenticated;
grant update(category_id,title,description,brand,model,city,condition,daily_rate,deposit_amount,quantity,image_url) on public.equipment_listings to authenticated;

-- A listing row is locked during allocation. Requests count against capacity immediately,
-- so parallel attempts cannot both allocate the last available unit.
create or replace function public.request_booking(p_listing_id uuid,p_start_at timestamptz,p_end_at timestamptz,p_quantity integer)
returns table(reference text,quoted_total bigint) language plpgsql security definer set search_path='' as $$
declare x public.equipment_listings%rowtype; occupied bigint; days_count integer; total bigint; b public.bookings%rowtype;
begin
 if auth.uid() is null then raise exception 'Login required';end if;
 if p_start_at<=now() or p_end_at<=p_start_at or p_end_at>p_start_at+interval '90 days' then raise exception 'Choose a valid rental period (maximum 90 days)';end if;
 if p_quantity<1 then raise exception 'Quantity must be at least one';end if;
 select * into x from public.equipment_listings where id=p_listing_id for update;
 if not found or x.status<>'published' then raise exception 'Equipment unavailable';end if;
 if x.owner_id=auth.uid() then raise exception 'You cannot rent your own equipment';end if;
 select coalesce(sum(quantity),0) into occupied from public.bookings where listing_id=x.id and status in ('awaiting_approval','awaiting_payment','confirmed','active','return_pending','disputed') and start_at<p_end_at and end_at>p_start_at;
 if occupied+p_quantity>x.quantity then raise exception 'Requested quantity is unavailable for these dates';end if;
 days_count:=ceil(extract(epoch from (p_end_at-p_start_at))/86400.0);
 if days_count>90 or (x.daily_rate::numeric*days_count*p_quantity+x.deposit_amount::numeric*p_quantity)>9223372036854775807 then raise exception 'Booking exceeds allowed limits';end if;
 total:=x.daily_rate*days_count*p_quantity+x.deposit_amount*p_quantity;
 insert into public.bookings(listing_id,customer_id,owner_id,start_at,end_at,quantity,quoted_subtotal,quoted_deposit,quoted_total)
 values(x.id,auth.uid(),x.owner_id,p_start_at,p_end_at,p_quantity,x.daily_rate*days_count*p_quantity,x.deposit_amount*p_quantity,total) returning * into b;
 insert into public.booking_status_history(booking_id,new_status,changed_by) values(b.id,b.status,auth.uid());
 return query select b.reference,b.quoted_total;
end$$;

create or replace function public.owner_booking_action(p_booking_id uuid,p_new_status text) returns void language plpgsql security definer set search_path='' as $$
declare b public.bookings%rowtype;
begin
 select * into b from public.bookings where id=p_booking_id for update;
 if not found or (b.owner_id<>auth.uid() and not public.is_admin()) then raise exception 'Not authorised';end if;
 if not ((b.status='awaiting_approval' and p_new_status in ('awaiting_payment','rejected')) or (b.status='confirmed' and p_new_status='active' and b.payment_status='verified') or (b.status='active' and p_new_status='return_pending')) then raise exception 'Invalid booking transition or missing verified payment';end if;
 update public.bookings set status=p_new_status,updated_at=now() where id=b.id;
 insert into public.booking_status_history(booking_id,old_status,new_status,changed_by) values(b.id,b.status,p_new_status,auth.uid());
end$$;

create or replace function public.admin_review(p_table text,p_record_id uuid,p_action text) returns void language plpgsql security definer set search_path='' as $$
begin
 if not public.is_admin() then raise exception 'Administrator access required';end if;
 if p_table='owner_profiles' and p_action='verified' then
 update public.owner_profiles set verified=true where user_id=p_record_id;
 elsif p_table='equipment_listings' and p_action in ('published','rejected') then
 if p_action='published' and not exists(select 1 from public.equipment_listings l join public.owner_profiles o on o.user_id=l.owner_id where l.id=p_record_id and o.verified) then raise exception 'Verify the owner before publishing';end if;
 update public.equipment_listings set status=p_action where id=p_record_id;
 else raise exception 'Invalid review action';end if;
 insert into public.audit_logs(actor_id,action,resource_type,resource_id) values(auth.uid(),p_action,p_table,p_record_id);
end$$;
revoke all on function public.request_booking(uuid,timestamptz,timestamptz,integer) from public;
revoke all on function public.owner_booking_action(uuid,text) from public;
revoke all on function public.admin_review(text,uuid,text) from public;
grant execute on function public.request_booking(uuid,timestamptz,timestamptz,integer),public.owner_booking_action(uuid,text),public.admin_review(text,uuid,text) to authenticated;

insert into public.categories(name) values ('Construction tools'),('Power tools'),('Hand tools'),('Generators and electrical'),('Welding equipment'),('Plumbing equipment'),('Painting equipment'),('Ladders and scaffolding'),('Agriculture equipment'),('Cleaning equipment'),('Event equipment'),('Industrial machinery'),('Photography and audiovisual');
