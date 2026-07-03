--[[
    HttpSpy v1.1.3 (+ spoofing support merged from spoofer.lua)
]]

local options = ({...})[1] or { AutoDecode = true, Highlighting = true, SaveLogs = true, CLICommands = true, ShowResponse = true, BlockedURLs = {}, API = true };
local version = "v1.1.3";
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
local blocked = options.BlockedURLs;
local enabled = true;
local reqfunc = (syn or http).request;
local libtype = syn and "syn" or "http";
local hooked = {};
local proxied = {};
local spoofs = {}; -- url/pattern -> function(RequestData) or static response table
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

local function FindSpoof(url)
    for target_url, modifier in Pairs(spoofs) do
        if find(url, target_url) then
            return modifier;
        end;
    end;
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

    local SpoofRule = FindSpoof(RequestData.Url);

    if not options.ShowResponse and not SpoofRule then
        printf("%s.request(%s)\n\n", libtype, Serializer.Serialize(RequestData));
        return __request(req);
    end;

    local t = crunning();
    cwrap(function()
        task.wait(); -- ensure the calling thread reaches cyield() before any cresume below;
                     -- real requests yield internally via __request, but spoofed/blocked
                     -- responses never touch the network, so without this cresume(t, ...)
                     -- fires while t is still running and crashes the client

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

        local ResponseData;
        if SpoofRule then
            if Type(SpoofRule) == "function" then
                local ok, fake = Pcall(SpoofRule, RequestData);
                ResponseData = (ok and fake) or {};
            elseif Type(SpoofRule) == "table" then
                ResponseData = SpoofRule;
            else
                ResponseData = {};
            end;
            printf("%s.request(%s) -- spoofed\n\n", libtype, Serializer.Serialize(RequestData));
        else
            local ok, RealResponse = Pcall(__request, RequestData); -- I know of a detection with this
            if not ok then
                Error(RealResponse, 0);
            end;
            ResponseData = RealResponse;
        end;

        local BackupData = {};
        for i,v in Pairs(ResponseData) do
            BackupData[i] = v;
        end;

        if BackupData.Headers and BackupData.Headers["Content-Type"] and match(BackupData.Headers["Content-Type"], "application/json") and options.AutoDecode then
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

-- Spoofing API (merged from spoofer.lua)
function API:SetSpoof(url_pattern, rule)
    -- rule can be a function(RequestData) -> fake response table, or a static response table
    spoofs[url_pattern] = rule;
end;

function API:RemoveSpoof(url_pattern)
    if not spoofs[url_pattern] then
        error("url isn't spoofed", 0);
    end;
    spoofs[url_pattern] = nil;
end;

function API:ClearSpoofs()
    spoofs = {};
end;

return API;
