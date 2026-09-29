import { afterEach, describe, expect, it, vi } from 'vitest';
import entry from './index.js';
import { getToolPluginMetadata } from 'openclaw/plugin-sdk/tool-plugin';
function tool(endpoint='https://pilot.example.test',name='inboxcheck_screen_email') {
 const registered:any={};
 entry.register({pluginConfig:{endpoint},registerTool:(t:any)=>{registered[t.name]=t;}} as any);
 return registered[name];
}
const params={text:'An email longer than twenty characters.',sanitized:true,shareForReview:false};
afterEach(()=>{vi.unstubAllGlobals();delete process.env.INBOXCHECK_AGENT_TOKEN;});
describe('rva-inboxcheck',()=>{
 it('declares the real tool',()=>expect(getToolPluginMetadata(entry)?.tools.map(t=>t.name)).toEqual(['inboxcheck_screen_email','inboxcheck_screen_ticket']));
 it('fails without a token',async()=>{await expect(tool().execute('id',params)).rejects.toThrow('token missing')});
 it('rejects insecure and credential-bearing endpoints',async()=>{
  for(const endpoint of ['http://pilot.example.test','https://user:password@pilot.example.test','https://pilot.example.test/unexpected'])await expect(tool(endpoint).execute('id',params)).rejects.toThrow('HTTPS pilot origin');
 });
 it('routes one bounded request without sharing by default',async()=>{
  process.env.INBOXCHECK_AGENT_TOKEN='test-token';let seen:any;
  vi.stubGlobal('fetch',vi.fn(async(url,options)=>{seen={url,options};return new Response(JSON.stringify({case_id:'synthetic',assessment:{risk:'suspicious'},shared:false}),{status:200})}));
  const r=await tool().execute('id',params);
  expect(seen.url.pathname).toBe('/api/agent/analyze');expect(seen.options.redirect).toBe('error');expect(JSON.parse(seen.options.body).share).toBe(false);expect(r.details.assessment.risk).toBe('suspicious');
 });
 it('never returns error bodies containing secrets',async()=>{
  process.env.INBOXCHECK_AGENT_TOKEN='test-token';vi.stubGlobal('fetch',vi.fn(async()=>new Response('leaked-secret',{status:503})));
  await expect(tool().execute('id',params)).rejects.toThrow('HTTP 503');
 });
 it('rejects invented verdicts',async()=>{
  process.env.INBOXCHECK_AGENT_TOKEN='test-token';vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify({case_id:'a',assessment:{risk:'safe'}}))));
  await expect(tool().execute('id',params)).rejects.toThrow('Invalid screening result');
 });
 it('ticket tool sends only the ticket and admits a result without a case id',async()=>{
  process.env.INBOXCHECK_AGENT_TOKEN='test-token';let seen:any;
  vi.stubGlobal('fetch',vi.fn(async(url,options)=>{seen={url,options};return new Response(JSON.stringify({assessment:{risk:'likely_phishing',signals:[{id:'requests_secrets',label:'x',strength:'strong'}]},explanation:{summary:'s',evidence:['e'],next_steps:['n'],limitations:'l'},shared:false,limitation:'x'}),{status:200})}));
  const r=await tool(undefined,'inboxcheck_screen_ticket').execute('id',{ticket:'A'.repeat(43)});
  expect(seen.url.pathname).toBe('/api/agent/screen');expect(JSON.parse(seen.options.body)).toEqual({ticket:'A'.repeat(43)});
  expect(r.details.assessment.risk).toBe('likely_phishing');expect(r.details.case_id).toBeUndefined();expect(r.details.untrusted_evidence.excerpts).toEqual(['e']);
 });
 it('ticket tool fails closed on errors',async()=>{
  process.env.INBOXCHECK_AGENT_TOKEN='test-token';vi.stubGlobal('fetch',vi.fn(async()=>new Response('nope',{status:404})));
  await expect(tool(undefined,'inboxcheck_screen_ticket').execute('id',{ticket:'A'.repeat(43)})).rejects.toThrow('HTTP 404');
 });
});
