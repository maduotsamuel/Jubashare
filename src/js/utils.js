export const escapeHtml=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const money=v=>new Intl.NumberFormat('en-SS',{maximumFractionDigits:0}).format(Number(v||0))+' SSP';
export const dateFmt=v=>v?new Date(v).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'}):'—';
export function errorMessage(error){return error?.message||'Something went wrong. Please try again.'}
export const qs=(q)=>document.querySelector(q);
export const field=(name,label,type='text',value='',extra='')=>`<label class="form-label fw-semibold" for="${name}">${label}</label><input id="${name}" name="${name}" type="${type}" class="form-control" value="${escapeHtml(value)}" ${extra}>`;
export function formObject(form){return Object.fromEntries(new FormData(form).entries())}
export function id(){return crypto.randomUUID()}
