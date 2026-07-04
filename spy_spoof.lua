--[[
    HttpSpy + DynamicSpoofEngine (merged)  v2.0.0
    Based on HttpSpy v1.1.3 by NotDSF + your DynamicSpoofEngine.

    Design goals:
      * Idempotent  - safe to execute any number of times. All hooks are
                      installed EXACTLY once. Re-running only refreshes the
                      live config + spoof rules; it never stacks a second hook.
      * Persistent  - everything that must survive across executions (originals,
                      the API, spoof rules, blocked/proxied tables, the log
                      handle) lives in getgenv()._G[KEY]. Edit the CONFIG /
                      SPOOF RULES section at the bottom and re-execute to update
                      behaviour live, no rejoin required.

    Access the API later from anywhere with:
        getgenv()._G.__HttpSpyEngine.API
    or the convenience alias:
        getgenv()._G.HttpSpy
]]

--=============================================================================
-- 0. PERSISTENT STORE
--=============================================================================
local GENV = getgenv()
GENV._G = GENV._G or {}                 -- executor global table
local KEY = "__HttpSpyEngine"

local passedOptions = ({ ... })[1]      -- optional options table on this run

--=============================================================================
-- 1. ONE-TIME ENGINE INSTALL  (runs only on the FIRST execution)
--=============================================================================
if not GENV._G[KEY] then
    -----------------------------------------------------------------------
    -- 1a. State container (the single source of truth, lives forever)
    -----------------------------------------------------------------------
    local State = {
        Version   = "2.0.0",
        Enabled   = true,               -- master switch for logging
        Options   = {
            AutoDecode   = true,
            Highlighting = true,
            SaveLogs     = true,
            ShowResponse = true,
            API          = true,
        },
        Spoofs    = {},                 -- [urlPattern] = table | function(req)
        Blocked   = {},                 -- [url] = true
        Proxied   = {},                 -- [host] = replacementHost
        Hooked    = {},                 -- [url] = function(response) -> response
        Originals = {},                 -- captured original functions
    }
    GENV._G[KEY] = State

    -----------------------------------------------------------------------
    -- 1b. Clone everything the hooks touch so our own calls stay un-hooked
    -----------------------------------------------------------------------
    local clonef      = clonefunction
    local pconsole    = clonef(rconsoleprint)
    local format      = clonef(string.format)
    local gsub        = clonef(string.gsub)
    local match       = clonef(string.match)
    local find        = clonef(string.find)
    local append      = clonef(appendfile)
    local Type        = clonef(type)
    local crunning    = clonef(coroutine.running)
    local cwrap       = clonef(coroutine.wrap)
    local cresume     = clonef(coroutine.resume)
    local cyield      = clonef(coroutine.yield)
    local Pcall       = clonef(pcall)
    local Pairs       = clonef(pairs)
    local Error       = clonef(error)
    local getnamecallmethod = clonef(getnamecallmethod)

    local reqfunc = (syn or http).request
    local libtype = syn and "syn" or "http"

    -----------------------------------------------------------------------
    -- 1c. Serializer (leopard) + log file, created once
    -----------------------------------------------------------------------
    local Serializer = loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/leopard/main/rbx/leopard-syn.lua"))()
    Serializer.UpdateConfig({ highlighting = State.Options.Highlighting })
    State.Serializer = Serializer

    local logname = format("%d-%s-log.txt", game.PlaceId, os.date("%d_%m_%y"))
    State.LogName = logname
    if State.Options.SaveLogs then
        writefile(logname, format("Http Logs from %s\n\n", os.date("%d/%m/%y")))
    end

    -- printf reads State live so SaveLogs can be toggled on re-run
    local function printf(...)
        if State.Options.SaveLogs then
            append(logname, gsub(format(...), "%\27%[%d+m", ""))
        end
        return pconsole(format(...))
    end
    State.Printf = printf

    -----------------------------------------------------------------------
    -- 1d. Helpers
    -----------------------------------------------------------------------
    local function DeepClone(tbl, cloned)
        cloned = cloned or {}
        for i, v in Pairs(tbl) do
            if Type(v) == "table" then
                cloned[i] = DeepClone(v)
            else
                cloned[i] = v
            end
        end
        return cloned
    end

    -- Find the first spoof rule whose pattern is contained in the URL
    local function MatchSpoof(url)
        for pattern, modifier in Pairs(State.Spoofs) do
            if find(url, pattern, 1, true) then   -- plain substring match
                return modifier
            end
        end
        return nil
    end

    local OnRequest = Instance.new("BindableEvent")
    State.OnRequestSignal = OnRequest

    -- namecall methods to log
    local methods = {
        HttpGet      = not syn,
        HttpGetAsync = not syn,
        GetObjects   = true,
        HttpPost     = not syn,
        HttpPostAsync = not syn,
    }

    -----------------------------------------------------------------------
    -- 1e. __namecall hook (install once)
    -----------------------------------------------------------------------
    local __namecall
    __namecall = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
        local method = getnamecallmethod()
        if State.Enabled and methods[method] then
            printf("game:%s(%s)\n\n", method, Serializer.FormatArguments(...))
        end
        return __namecall(self, ...)
    end))
    State.Originals.namecall = __namecall

    -----------------------------------------------------------------------
    -- 1f. request hook (install once) -- combines SPOOF + BLOCK + PROXY + LOG
    -----------------------------------------------------------------------
    local __request
    __request = hookfunction(reqfunc, newcclosure(function(req)
        local S = GENV._G[KEY]
        if Type(req) ~= "table" or Type(req.Url) ~= "string" then
            return __request(req)
        end

        local RequestData = DeepClone(req)

        -----------------------------------------------------------------
        -- SPOOF  (synchronous return -- no yield, so no coroutine dance)
        -----------------------------------------------------------------
        local rule = MatchSpoof(RequestData.Url)
        if rule then
            local fake
            if Type(rule) == "function" then
                local ok, res = Pcall(rule, RequestData)
                if ok then fake = res end
            elseif Type(rule) == "table" then
                fake = rule
            end
            if fake then
                if S.Options.ShowResponse then
                    printf("%s.request(%s) -- SPOOFED\n\nResponse Data: %s\n\n",
                        libtype, Serializer.Serialize(RequestData), Serializer.Serialize(fake))
                else
                    printf("%s.request(%s) -- SPOOFED\n\n", libtype, Serializer.Serialize(RequestData))
                end
                return fake
            end
        end

        -----------------------------------------------------------------
        -- BLOCK  (synchronous return)
        -----------------------------------------------------------------
        if S.Blocked[RequestData.Url] then
            printf("%s.request(%s) -- blocked url\n\n", libtype, Serializer.Serialize(RequestData))
            return {}
        end

        -----------------------------------------------------------------
        -- PROXY host rewrite
        -----------------------------------------------------------------
        local Host = match(RequestData.Url, "https?://(%w+%.%w+)/")
        if Host and S.Proxied[Host] then
            RequestData.Url = gsub(RequestData.Url, Host, S.Proxied[Host], 1)
        end

        OnRequest:Fire(RequestData)

        -----------------------------------------------------------------
        -- REAL REQUEST  (needs to yield -> trampoline through a coroutine
        -- because you cannot yield across a newcclosure boundary)
        -----------------------------------------------------------------
        local t = crunning()
        cwrap(function()
            local ok, ResponseData = Pcall(__request, RequestData)
            if not ok then
                return cresume(t, nil, ResponseData)   -- propagate error to caller
            end

            -- log-only fast path
            if not S.Enabled then
                return cresume(t, S.Hooked[RequestData.Url] and S.Hooked[RequestData.Url](ResponseData) or ResponseData)
            end

            if not S.Options.ShowResponse then
                printf("%s.request(%s)\n\n", libtype, Serializer.Serialize(RequestData))
                return cresume(t, S.Hooked[RequestData.Url] and S.Hooked[RequestData.Url](ResponseData) or ResponseData)
            end

            -- copy response for display so AutoDecode doesn't mutate the real body
            local BackupData = {}
            for i, v in Pairs(ResponseData) do
                BackupData[i] = v
            end

            if BackupData.Headers and BackupData.Headers["Content-Type"]
                and match(BackupData.Headers["Content-Type"], "application/json")
                and S.Options.AutoDecode then
                local okd, res = Pcall(game.HttpService.JSONDecode, game.HttpService, BackupData.Body)
                if okd then BackupData.Body = res end
            end

            printf("%s.request(%s)\n\nResponse Data: %s\n\n",
                libtype, Serializer.Serialize(RequestData), Serializer.Serialize(BackupData))

            cresume(t, S.Hooked[RequestData.Url] and S.Hooked[RequestData.Url](ResponseData) or ResponseData)
        end)()

        local result, err = cyield()
        if err then Error(err, 0) end
        return result
    end))
    State.Originals.request = __request

    if request then
        replaceclosure(request, reqfunc)
    end

    -----------------------------------------------------------------------
    -- 1g. game.HttpGet / HttpPost / GetObjects hooks (install once)
    -----------------------------------------------------------------------
    State.Originals.methods = {}
    for method, on in Pairs(methods) do
        if on then
            local b
            b = hookfunction(game[method], newcclosure(function(self, ...)
                local S = GENV._G[KEY]
                if S.Enabled then
                    printf("game.%s(game, %s)\n\n", method, Serializer.FormatArguments(...))
                end
                return b(self, ...)
            end))
            State.Originals.methods[method] = b
        end
    end

    -----------------------------------------------------------------------
    -- 1h. Public API (built once, stored forever)
    -----------------------------------------------------------------------
    local API = {}
    API.OnRequest = OnRequest.Event

    -- spoofing
    function API:AddSpoof(pattern, modifier)   -- modifier: table | function(req)
        State.Spoofs[pattern] = modifier
    end
    function API:RemoveSpoof(pattern)
        State.Spoofs[pattern] = nil
    end
    function API:ClearSpoofs()
        State.Spoofs = {}
    end
    function API:GetSpoofs()
        return State.Spoofs
    end

    -- response hooking / proxy / blocking (from HttpSpy)
    function API:HookSynRequest(url, hook)  State.Hooked[url] = hook end
    function API:UnHookSynRequest(url)
        if not State.Hooked[url] then Error("url isn't hooked", 0) end
        State.Hooked[url] = nil
    end
    function API:ProxyHost(host, proxy)     State.Proxied[host] = proxy end
    function API:RemoveProxy(host)
        if not State.Proxied[host] then Error("host isn't proxied", 0) end
        State.Proxied[host] = nil
    end
    function API:BlockUrl(url)      State.Blocked[url] = true  end
    function API:WhitelistUrl(url)  State.Blocked[url] = false end

    -- logging control
    function API:Enable()  State.Enabled = true  end
    function API:Disable() State.Enabled = false end
    function API:SetOption(name, value) State.Options[name] = value end

    State.API = API
    GENV._G.HttpSpy = API   -- convenience alias

    pconsole(format("[HttpSpy+Spoofer %s] Engine installed. Hooks are live.\n", State.Version))
end

--=============================================================================
-- 2. LIVE CONFIG  (runs EVERY execution -- refreshes options + spoof rules)
--    Edit below and re-execute to update behaviour without rejoining.
--=============================================================================
local State = GENV._G[KEY]

-- Merge any options passed as the first vararg on this run
if type(passedOptions) == "table" then
    for k, v in pairs(passedOptions) do
        State.Options[k] = v
    end
    if State.Serializer and passedOptions.Highlighting ~= nil then
        State.Serializer.UpdateConfig({ highlighting = passedOptions.Highlighting })
    end
end

-- Reset spoof rules so edits/removals take effect cleanly on re-run
State.Spoofs = {}

-----------------------------------------------------------------------------
-- YOUR ACTIVE SPOOF RULES
-- key   = substring to match in the request URL (plain match, not a pattern)
-- value = either a static response table, or function(req) -> response table
-----------------------------------------------------------------------------

-- Static example: any URL containing "example" returns this table instantly
State.Spoofs["example"] = {
    StatusCode = 200,
    Success    = true,
    Body       = "data",
}

-- Dynamic example: inspect the outgoing request and build a response
-- State.Spoofs["api/getcoins"] = function(req)
--     return {
--         StatusCode = 200,
--         Success    = true,
--         Body       = game:GetService("HttpService"):JSONEncode({ coins = 999999 }),
--     }
-- end

-----------------------------------------------------------------------------

State.Printf("[HttpSpy+Spoofer] Config refreshed. Active spoof rules: ")
do
    local n = 0
    for _ in pairs(State.Spoofs) do n = n + 1 end
    State.Printf("%d\n\n", n)
end

return State.API