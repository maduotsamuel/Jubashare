import {createClient} from '@supabase/supabase-js';
const url=window.JAMB_CONFIG?.supabaseUrl;
const key=window.JAMB_CONFIG?.supabasePublishableKey;
export const configured=!!(url&&key&&!url.includes('YOUR_PROJECT'));
export const db=configured?createClient(url,key,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}}):null;
export async function requireResult(promise){const {data,error}=await promise;if(error)throw error;return data}
export async function session(){if(!db)return null;return (await db.auth.getUser()).data.user}
export async function roles(userId){if(!userId)return [];return (await requireResult(db.from('user_roles').select('role').eq('user_id',userId))).map(x=>x.role)}
export async function getListings(params={}){let q=db.from('equipment_listings').select('id,title,description,brand,model,city,daily_rate,deposit_amount,image_url,condition,status,owner_id,categories(name)',{count:'exact'}).eq('status','published');if(params.term)q=q.ilike('title',`%${params.term.replaceAll('%','')}%`);if(params.category)q=q.eq('category_id',params.category);if(params.city)q=q.ilike('city',`%${params.city.replaceAll('%','')}%`);q=q.order('created_at',{ascending:false}).range(params.page*12||0,(params.page*12||0)+11);const {data,error,count}=await q;if(error)throw error;return {data,count}}
export const categories=()=>requireResult(db.from('categories').select('id,name').order('name'));
export const listing=id=>requireResult(db.from('equipment_listings').select('*,categories(name),owner_profiles(business_name,verified)').eq('id',id).eq('status','published').single());
export const myBookings=user=>requireResult(db.from('bookings').select('id,reference,status,start_at,end_at,quantity,quoted_total,payment_status,equipment_listings(title)').eq('customer_id',user).order('created_at',{ascending:false}));
export const ownerListings=user=>requireResult(db.from('equipment_listings').select('id,title,status,daily_rate,city,quantity,created_at').eq('owner_id',user).order('created_at',{ascending:false}));
export const ownerBookings=user=>requireResult(db.from('bookings').select('id,reference,status,start_at,end_at,quantity,quoted_total,equipment_listings(title)').eq('owner_id',user).order('created_at',{ascending:false}));
