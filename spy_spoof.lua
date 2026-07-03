--[[
    HttpSpy v1.1.3 (spoof-enabled)

    Merge of HttpSpy's request logger with a static/dynamic response spoof
    engine. Everything HttpSpy already did (logging, proxying, blocking,
    response hooks, auto JSON decode) still works. On top of that you can now
    register spoof rules that short-circuit the real request and return a
    fabricated response.

    A spoof rule can be:
        * a table    -> returned as-is as the response (defaults filled in)
        * a function -> function(requestData) that returns a response table

    Rule keys are matched against the request URL with string.find (Lua
    pattern), matching spoofer.lua's original behaviour.

    New API:
        API:Spoof(urlPattern, response)   -- table (static) or function(req) -> table (dynamic)
        API:UnSpoof(urlPattern)
        API:ClearSpoofs()

    You can also seed rules up front:  options.Spoofs = { ["pattern"] = ... }

    Note: a matched spoof rule takes precedence over BlockedURLs for the same
    URL, and never touches the network.

    Safe to run more than once per session: the hooks install only on the first
    run. Re-running merges any newly-passed options.Spoofs / options.BlockedURLs
    into the live tables and returns the SAME API object, so nothing stacks.
    Preferred workflow: keep the returned API and call API:Spoof(...) directly
    to add rules mid-session as you read outputs.
]]

local options = ({...})[1] or { AutoDecode = true, Highlighting = true, SaveLogs = true, CLICommands = true, ShowResponse = true, BlockedURLs = {}, Spoofs = {}, API = true };
local version = "v1.1.3";
local STORE_KEY = "__HttpSpyEngine";
-- Cross-execution state must live in the executor's persistent global env.
-- `shared` (and `_G`) are reset/sandboxed per run in many executors, so a guard
-- keyed to `shared` reads nil every run and the hooks stack. getgenv() persists.
local ENV = (type(getgenv) == "function" and getgenv()) or shared or _G;

-- Re-run guard: hooks install only on the first run this session. On a re-run we
-- merge any newly-passed rules into the live tables and hand back the same API,
-- so re-running to add spoofs never stacks duplicate hooks or wipes the log.
if ENV[STORE_KEY] and ENV[STORE_KEY].installed then
    local store = ENV[STORE_KEY];
    if type(options.Spoofs) == "table" then
        for k, v in pairs(options.Spoofs) do store.spoofs[k] = v; end;
    end;
    if type(options.BlockedURLs) == "table" then
        for k, v in pairs(options.BlockedURLs) do store.blocked[k] = v; end;
    end;
    print("[HttpSpy] Already active this session -- returning existing API (hooks not re-installed).");
    return store.API;
end;

local logname = string.format("%d-%s-log.txt", game.PlaceId, os.date("%d_%m_%y"));

if options.SaveLogs then
    writefile(logname, string.format("Http Logs from %s\n\n", os.date("%d/%m/%y"))) 
end;

local Serializer = loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/leopard/main/rbx/leopard-syn.lua"))();
local clonef = clonefunction;
local pconsole = clonef(rconsoleprint);
local format = clonef(string.format);
local gsub = clonef(string.gsub);
local match = clonef(string.match);
local find = clonef(string.find);
local append = clonef(appendfile);
local Type = clonef(type);
local crunning = clonef(coroutine.running);
local cwrap = clonef(coroutine.wrap);
local cresume = clonef(coroutine.resume);
local cyield = clonef(coroutine.yield);
local Pcall = clonef(pcall);
local Pairs = clonef(pairs);
local Error = clonef(error);
local getnamecallmethod = clonef(getnamecallmethod);
-- Persistent state kept in the executor global env so re-runs reuse the tables.
ENV[STORE_KEY] = ENV[STORE_KEY] or {};
local store = ENV[STORE_KEY];
store.spoofs  = store.spoofs  or (options.Spoofs or {});
store.blocked = store.blocked or (options.BlockedURLs or {});
store.hooked  = store.hooked  or {};
store.proxied = store.proxied or {};

local blocked = store.blocked;
local spoofs  = store.spoofs;
local hooked  = store.hooked;
local proxied = store.proxied;
local enabled = true;
local reqfunc = (syn or http).request;
local libtype = syn and "syn" or "http";
local methods = {
    HttpGet = not syn,
    HttpGetAsync = not syn,
    GetObjects = true,
    HttpPost = not syn,
    HttpPostAsync = not syn
}

Serializer.UpdateConfig({ highlighting = options.Highlighting });

local RecentCommit = game.HttpService:JSONDecode(game:HttpGet("https://api.github.com/repos/NotDSF/HttpSpy/commits?per_page=1&path=init.lua"))[1].commit.message;
local OnRequest = Instance.new("BindableEvent");

local function printf(...) 
    if options.SaveLogs then
        append(logname, gsub(format(...), "%\27%[%d+m", ""));
    end;
    return pconsole(format(...));
end;

local function ConstantScan(constant)
    for i,v in Pairs(getgc(true)) do
        if type(v) == "function" and islclosure(v) and getfenv(v).script == getfenv(saveinstance).script and table.find(debug.getconstants(v), constant) then
            return v;
        end;
    end;
end;

local function DeepClone(tbl, cloned)
    cloned = cloned or {};

    for i,v in Pairs(tbl) do
        if Type(v) == "table" then
            cloned[i] = DeepClone(v);
            continue;
        end;
        cloned[i] = v;
    end;

    return cloned;
end;

-- Return the first spoof rule whose key matches the URL (string.find / Lua pattern).
local function MatchSpoof(url)
    if Type(url) ~= "string" then return nil; end;
    for pattern, modifier in Pairs(spoofs) do
        if find(url, pattern) then
            return modifier;
        end;
    end;
    return nil;
end;

-- Turn a spoof rule (table = static, function = dynamic) into a full response table.
local function BuildSpoof(rule, requestData)
    local FakeResponse;
    if Type(rule) == "function" then
        local ok, generated = Pcall(rule, requestData);
        if not ok then
            Error(generated, 0);
        end;
        FakeResponse = generated;
    elseif Type(rule) == "table" then
        FakeResponse = DeepClone(rule);
    end;

    if Type(FakeResponse) ~= "table" then
        return nil;
    end;

    -- Fill in sensible defaults so downstream consumers don't choke on a partial response.
    FakeResponse.Headers = FakeResponse.Headers or {};
    if FakeResponse.StatusCode == nil then FakeResponse.StatusCode = 200; end;
    if FakeResponse.StatusText == nil then FakeResponse.StatusText = "OK"; end;
    if FakeResponse.Success == nil then FakeResponse.Success = FakeResponse.StatusCode >= 200 and FakeResponse.StatusCode < 300; end;
    if FakeResponse.Body == nil then FakeResponse.Body = ""; end;

    return FakeResponse;
end;

local __namecall, __request;
__namecall = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
    local method = getnamecallmethod();

    if methods[method] then
        printf("game:%s(%s)\n\n", method, Serializer.FormatArguments(...));
    end;

    return __namecall(self, ...);
end));

__request = hookfunction(reqfunc, newcclosure(function(req) 
    if Type(req) ~= "table" then return __request(req); end;
    
    local RequestData = DeepClone(req);
    if not enabled then
        return __request(req);
    end;

    if Type(RequestData.Url) ~= "string" then return __request(req) end;

    -- Spoofing: if a rule matches, fabricate the response and skip the network entirely.
    -- Handled synchronously here (rather than inside the async yield/resume block) so a
    -- static/dynamic spoof never tries to resume a thread that is still running.
    local spoofRule = MatchSpoof(RequestData.Url);
    if spoofRule then
        OnRequest:Fire(RequestData);

        local FakeResponse = BuildSpoof(spoofRule, RequestData);
        if FakeResponse then
            if options.ShowResponse then
                local BackupData = DeepClone(FakeResponse);
                if BackupData.Headers and BackupData.Headers["Content-Type"] and match(BackupData.Headers["Content-Type"], "application/json") and options.AutoDecode then
                    local ok, res = Pcall(game.HttpService.JSONDecode, game.HttpService, BackupData.Body);
                    if ok then
                        BackupData.Body = res;
                    end;
                end;
                printf("%s.request(%s) -- spoofed\n\nResponse Data: %s\n\n", libtype, Serializer.Serialize(RequestData), Serializer.Serialize(BackupData));
            else
                printf("%s.request(%s) -- spoofed\n\n", libtype, Serializer.Serialize(RequestData));
            end;

            return hooked[RequestData.Url] and hooked[RequestData.Url](FakeResponse) or FakeResponse;
        end;
    end;

    if not options.ShowResponse then
        printf("%s.request(%s)\n\n", libtype, Serializer.Serialize(RequestData));
        return __request(req);
    end;

    local t = crunning();
    cwrap(function() 
        if RequestData.Url and blocked[RequestData.Url] then
            printf("%s.request(%s) -- blocked url\n\n", libtype, Serializer.Serialize(RequestData));
            return cresume(t, {});
        end;

        if RequestData.Url then
            local Host = string.match(RequestData.Url, "https?://(%w+.%w+)/");
            if Host and proxied[Host] then
                RequestData.Url = gsub(RequestData.Url, Host, proxied[Host], 1);
            end; 
        end;

        OnRequest:Fire(RequestData);

        local ok, ResponseData = Pcall(__request, RequestData); -- I know of a detection with this
        if not ok then
            Error(ResponseData, 0);
        end;

        local BackupData = {};
        for i,v in Pairs(ResponseData) do
            BackupData[i] = v;
        end;

        if BackupData.Headers["Content-Type"] and match(BackupData.Headers["Content-Type"], "application/json") and options.AutoDecode then
            local body = BackupData.Body;
            local ok, res = Pcall(game.HttpService.JSONDecode, game.HttpService, body);
            if ok then
                BackupData.Body = res;
            end;
        end;

        printf("%s.request(%s)\n\nResponse Data: %s\n\n", libtype, Serializer.Serialize(RequestData), Serializer.Serialize(BackupData));
        cresume(t, hooked[RequestData.Url] and hooked[RequestData.Url](ResponseData) or ResponseData);
    end)();
    return cyield();
end));

if request then
    replaceclosure(request, reqfunc);
end;

for method, enabled in Pairs(methods) do
    if enabled then
        local b;
        b = hookfunction(game[method], newcclosure(function(self, ...) 
            printf("game.%s(game, %s)\n\n", method, Serializer.FormatArguments(...));
            return b(self, ...);
        end));
    end;
end;

if not debug.info(2, "f") then
    pconsole("You are running an outdated version, please use the loadstring at https://github.com/NotDSF/HttpSpy\n");
end;

store.installed = true;

if not options.API then return end;

local API = {};
API.OnRequest = OnRequest.Event;

function API:HookSynRequest(url, hook) 
    hooked[url] = hook;
end;

function API:ProxyHost(host, proxy) 
    proxied[host] = proxy;
end;

function API:RemoveProxy(host) 
    if not proxied[host] then
        error("host isn't proxied", 0);
    end;
    proxied[host] = nil;
end;

function API:UnHookSynRequest(url) 
    if not hooked[url] then
        error("url isn't hooked", 0);
    end;
    hooked[url] = nil;
end

function API:BlockUrl(url) 
    blocked[url] = true;
end;

function API:WhitelistUrl(url) 
    blocked[url] = false;
end;

-- Register a spoof rule.
--   url      : Lua pattern matched against the request URL with string.find
--   response : table (static response) or function(requestData) -> response table
function API:Spoof(url, response) 
    spoofs[url] = response;
end;

function API:UnSpoof(url) 
    if not spoofs[url] then
        error("url isn't spoofed", 0);
    end;
    spoofs[url] = nil;
end;

function API:ClearSpoofs() 
    table.clear(spoofs);
end;

store.API = API;
return API;
