-- Apply after the foundation migration.
create table if not exists public.owner_verification_requests (
 owner_id uuid primary key references public.owner_profiles(user_id) on delete cascade,
 owner_type text not null check(owner_type in ('individual','business')),
 phone text not null check(length(trim(phone)) between 6 and 35),
 location text not null check(length(trim(location)) between 2 and 150),
 business_registration text,
 document_path text not null,
 status text not null default 'submitted' check(status in ('submitted','approved','rejected')),
 submitted_at timestamptz not null default now(),
 reviewed_at timestamptz,
 reviewed_by uuid references auth.users(id),
 review_note text
);
create or replace function public.protect_owner_application() returns trigger language plpgsql set search_path='' as $$
begin
 if tg_op='INSERT' then
   if new.owner_id<>auth.uid() or new.status<>'submitted' then raise exception 'Invalid owner application'; end if;
 else
   if not public.is_admin() then
     if new.owner_id is distinct from old.owner_id or new.status<>'submitted' or new.reviewed_at is distinct from old.reviewed_at or new.reviewed_by is distinct from old.reviewed_by or new.review_note is distinct from old.review_note then raise exception 'Not authorised to review'; end if;
   end if;
 end if;
 return new;
end$$;
create trigger protect_owner_application before insert or update on public.owner_verification_requests for each row execute function public.protect_owner_application();
alter table public.owner_verification_requests enable row level security;
create policy owner_application_read on public.owner_verification_requests for select to authenticated using(owner_id=(select auth.uid()) or public.is_admin());
create policy owner_application_create on public.owner_verification_requests for insert to authenticated with check(owner_id=(select auth.uid()) and status='submitted');
create policy owner_application_update on public.owner_verification_requests for update to authenticated using(owner_id=(select auth.uid()) or public.is_admin()) with check(owner_id=(select auth.uid()) or public.is_admin());
grant select on public.owner_verification_requests to authenticated;
grant insert(owner_id,owner_type,phone,location,business_registration,document_path,status,submitted_at) on public.owner_verification_requests to authenticated;
grant update(owner_type,phone,location,business_registration,document_path,status,submitted_at) on public.owner_verification_requests to authenticated;
-- Private bucket. Storage's RLS applies to objects, not to public owner profiles.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('owner-verification','owner-verification',false,5242880,array['application/pdf','image/png','image/jpeg'])
on conflict(id) do update set public=false,file_size_limit=5242880,allowed_mime_types=excluded.allowed_mime_types;
create policy owner_verification_upload on storage.objects for insert to authenticated
with check(bucket_id='owner-verification' and (storage.foldername(name))[1]=(select auth.uid())::text);
create policy owner_verification_read on storage.objects for select to authenticated
using(bucket_id='owner-verification' and ((storage.foldername(name))[1]=(select auth.uid())::text or public.is_admin()));
-- Force an application to exist before administrators approve an owner.
create or replace function public.admin_review(p_table text,p_record_id uuid,p_action text) returns void language plpgsql security definer set search_path='' as $$
begin
 if not public.is_admin() then raise exception 'Administrator access required';end if;
 if p_table='owner_profiles' and p_action in ('verified','rejected') then
   if p_action='verified' then
     if not exists(select 1 from public.owner_verification_requests where owner_id=p_record_id and status='submitted' and length(document_path)>0) then raise exception 'Submitted verification document required';end if;
     update public.owner_profiles set verified=true where user_id=p_record_id;
     update public.owner_verification_requests set status='approved',reviewed_at=now(),reviewed_by=auth.uid() where owner_id=p_record_id;
   else
     update public.owner_profiles set verified=false where user_id=p_record_id;
     update public.owner_verification_requests set status='rejected',reviewed_at=now(),reviewed_by=auth.uid(),review_note='Please contact JAMB support for the reason and resubmit.' where owner_id=p_record_id;
   end if;
 elsif p_table='equipment_listings' and p_action in ('published','rejected') then
   if p_action='published' and not exists(select 1 from public.equipment_listings l join public.owner_profiles o on o.user_id=l.owner_id where l.id=p_record_id and o.verified) then raise exception 'Verify the owner before publishing';end if;
   update public.equipment_listings set status=p_action where id=p_record_id;
 else raise exception 'Invalid review action';end if;
 insert into public.audit_logs(actor_id,action,resource_type,resource_id) values(auth.uid(),p_action,p_table,p_record_id);
end$$;
-- Prevent unverified providers from confirming or handing over bookings that predate revocation.
