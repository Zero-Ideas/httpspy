--[[
    HttpSpy + DynamicSpoofEngine (merged)  v2.1.0

    Fixes vs 2.0.0:
      * The global is now published to getgenv()._G ONLY after the whole
        install succeeds. A partial failure no longer leaves a half-built
        state with a missing .API -- the next run just retries cleanly.
      * Console / filesystem functions (rconsoleprint, appendfile, writefile,
        replaceclosure) are now optional. If your executor lacks them the
        engine still installs; it just degrades logging instead of erroring.
      * Hooks read the State upvalue directly (not a global lookup), removing
        the tiny window where a request during install could see a nil state.

    API access after load:
        local API = loadstring(game:HttpGet(url))()
        getgenv()._G.HttpSpy
        getgenv()._G.__HttpSpyEngine.API
]]

local GENV = getgenv()
GENV._G = GENV._G or {}
local KEY = "__HttpSpyEngine"
local passedOptions = ({ ... })[1]

--=============================================================================
-- 1. ONE-TIME ENGINE INSTALL (publishes to _G only on full success)
--=============================================================================
-- Treat "table present but .API missing" as NOT installed. That state can only
-- come from an old early-publish build that died before placing any hooks, so
-- rebuilding over it is safe (no hooks to duplicate).
if not (GENV._G[KEY] and GENV._G[KEY].API) then
    GENV._G[KEY] = nil   -- drop any stale/poisoned table before rebuilding

    -- Build everything against this LOCAL table; publish at the very end.
    local State = {
        Version   = "2.1.2",
        Enabled   = true,
        Options   = { AutoDecode = true, Highlighting = true, SaveLogs = true, ShowResponse = true, API = true },
        Spoofs    = {},
        Blocked   = {},
        Proxied   = {},
        Hooked    = {},
        Originals = {},
    }

    -----------------------------------------------------------------------
    -- Clones with fallbacks for functions not every executor exposes
    -----------------------------------------------------------------------
    local clonef = clonefunction or function(f) return f end

    -- required core (if these are missing the tool genuinely can't run)
    assert(hookfunction,       "executor missing hookfunction")
    assert(hookmetamethod,     "executor missing hookmetamethod")
    assert(newcclosure,        "executor missing newcclosure")
    assert(getnamecallmethod,  "executor missing getnamecallmethod")

    -- optional: console output
    local pconsole = rconsoleprint and clonef(rconsoleprint) or function(...) return print(...) end
    -- optional: file logging
    local append   = appendfile and clonef(appendfile) or nil
    local canFile  = (writefile and append) and true or false

    local format   = clonef(string.format)
    local gsub     = clonef(string.gsub)
    local match    = clonef(string.match)
    local find     = clonef(string.find)
    local Type     = clonef(type)
    local crunning = clonef(coroutine.running)
    local cwrap    = clonef(coroutine.wrap)
    local cresume  = clonef(coroutine.resume)
    local cyield   = clonef(coroutine.yield)
    local Pcall    = clonef(pcall)
    local Pairs    = clonef(pairs)
    local Error    = clonef(error)
    local getncm   = clonef(getnamecallmethod)

    local reqfunc = (syn or http) and (syn or http).request or request
    assert(reqfunc, "executor missing an HTTP request function")
    local libtype = syn and "syn" or "http"

    -----------------------------------------------------------------------
    -- Serializer (leopard). Failure here is fine -- we haven't published,
    -- so the next run retries. Falls back to tostring if unreachable.
    -----------------------------------------------------------------------
    local Serializer
    do
        local ok, s = pcall(function()
            return loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/leopard/main/rbx/leopard-syn.lua"))()
        end)
        if ok and type(s) == "table" then
            Serializer = s
            pcall(Serializer.UpdateConfig, { highlighting = State.Options.Highlighting })
        else
            Serializer = {
                Serialize       = function(v) return tostring(v) end,
                FormatArguments = function(...) return tostring(...) end,
                UpdateConfig    = function() end,
            }
        end
    end
    State.Serializer = Serializer

    local logname = format("%d-%s-log.txt", game.PlaceId, os.date("%d_%m_%y"))
    State.LogName = logname
    if canFile and State.Options.SaveLogs then
        pcall(writefile, logname, format("Http Logs from %s\n\n", os.date("%d/%m/%y")))
    end

    local function printf(...)
        if canFile and State.Options.SaveLogs then
            pcall(append, logname, gsub(format(...), "%\27%[%d+m", ""))
        end
        return pconsole(format(...))
    end
    State.Printf = printf

    local function DeepClone(tbl, cloned)
        cloned = cloned or {}
        for i, v in Pairs(tbl) do
            if Type(v) == "table" then cloned[i] = DeepClone(v) else cloned[i] = v end
        end
        return cloned
    end

    local function MatchSpoof(url)
        for pattern, modifier in Pairs(State.Spoofs) do
            if find(url, pattern, 1, true) then return modifier end
        end
        return nil
    end

    local OnRequest = Instance.new("BindableEvent")
    State.OnRequestSignal = OnRequest

    local methods = {
        HttpGet = not syn, HttpGetAsync = not syn, GetObjects = true,
        HttpPost = not syn, HttpPostAsync = not syn,
    }

    -----------------------------------------------------------------------
    -- __namecall hook
    -----------------------------------------------------------------------
    local __namecall
    __namecall = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
        local m = getncm()
        if State.Enabled and methods[m] then
            printf("game:%s(%s)\n\n", m, Serializer.FormatArguments(...))
        end
        return __namecall(self, ...)
    end))
    State.Originals.namecall = __namecall

    -----------------------------------------------------------------------
    -- request hook: SPOOF + BLOCK + PROXY + LOG (reads State upvalue)
    -----------------------------------------------------------------------
    local __request
    __request = hookfunction(reqfunc, newcclosure(function(req)
        if Type(req) ~= "table" or Type(req.Url) ~= "string" then
            return __request(req)
        end

        local RequestData = DeepClone(req)

        -- SPOOF (synchronous return, no yield)
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
                if State.Options.ShowResponse then
                    printf("%s.request(%s) -- SPOOFED\n\nResponse Data: %s\n\n",
                        libtype, Serializer.Serialize(RequestData), Serializer.Serialize(fake))
                else
                    printf("%s.request(%s) -- SPOOFED\n\n", libtype, Serializer.Serialize(RequestData))
                end
                return fake
            end
        end

        -- BLOCK
        if State.Blocked[RequestData.Url] then
            printf("%s.request(%s) -- blocked url\n\n", libtype, Serializer.Serialize(RequestData))
            return {}
        end

        -- PROXY
        local Host = match(RequestData.Url, "https?://(%w+%.%w+)/")
        if Host and State.Proxied[Host] then
            RequestData.Url = gsub(RequestData.Url, Host, State.Proxied[Host], 1)
        end

        OnRequest:Fire(RequestData)

        -- REAL REQUEST (trampoline: cannot yield across newcclosure)
        local t = crunning()
        cwrap(function()
            local ok, ResponseData = Pcall(__request, RequestData)
            if not ok then return cresume(t, nil, ResponseData) end

            if not State.Enabled then
                return cresume(t, State.Hooked[RequestData.Url] and State.Hooked[RequestData.Url](ResponseData) or ResponseData)
            end

            if not State.Options.ShowResponse then
                printf("%s.request(%s)\n\n", libtype, Serializer.Serialize(RequestData))
                return cresume(t, State.Hooked[RequestData.Url] and State.Hooked[RequestData.Url](ResponseData) or ResponseData)
            end

            local BackupData = {}
            for i, v in Pairs(ResponseData) do BackupData[i] = v end

            if BackupData.Headers and BackupData.Headers["Content-Type"]
                and match(BackupData.Headers["Content-Type"], "application/json")
                and State.Options.AutoDecode then
                local okd, res = Pcall(game.HttpService.JSONDecode, game.HttpService, BackupData.Body)
                if okd then BackupData.Body = res end
            end

            printf("%s.request(%s)\n\nResponse Data: %s\n\n",
                libtype, Serializer.Serialize(RequestData), Serializer.Serialize(BackupData))
            cresume(t, State.Hooked[RequestData.Url] and State.Hooked[RequestData.Url](ResponseData) or ResponseData)
        end)()

        local result, err = cyield()
        if err then Error(err, 0) end
        return result
    end))
    State.Originals.request = __request

    if request and replaceclosure then
        pcall(replaceclosure, request, reqfunc)
    end

    -----------------------------------------------------------------------
    -- game.HttpGet / HttpPost / GetObjects hooks
    -- Not every executor adds all of these to the DataModel. Indexing a
    -- missing one (e.g. game.HttpPost on some executors) THROWS, which would
    -- abort install after the request hook is already placed. So probe each
    -- one safely and only hook the ones that actually exist.
    -----------------------------------------------------------------------
    State.Originals.methods = {}
    for _, method in Pairs({ "HttpGet", "HttpGetAsync", "GetObjects", "HttpPost", "HttpPostAsync" }) do
        local ok, fn = pcall(function() return game[method] end)
        if ok and Type(fn) == "function" then
            local b
            b = hookfunction(fn, newcclosure(function(self, ...)
                if State.Enabled then
                    printf("game.%s(game, %s)\n\n", method, Serializer.FormatArguments(...))
                end
                return b(self, ...)
            end))
            State.Originals.methods[method] = b
        end
    end

    -----------------------------------------------------------------------
    -- Public API
    -----------------------------------------------------------------------
    local API = {}
    API.OnRequest = OnRequest.Event

    function API:AddSpoof(pattern, modifier) State.Spoofs[pattern] = modifier end
    function API:RemoveSpoof(pattern)        State.Spoofs[pattern] = nil      end
    function API:ClearSpoofs()               State.Spoofs = {}                end
    function API:GetSpoofs()                 return State.Spoofs              end

    function API:HookSynRequest(url, hook)   State.Hooked[url] = hook         end
    function API:UnHookSynRequest(url)
        if not State.Hooked[url] then Error("url isn't hooked", 0) end
        State.Hooked[url] = nil
    end
    function API:ProxyHost(host, proxy)      State.Proxied[host] = proxy      end
    function API:RemoveProxy(host)
        if not State.Proxied[host] then Error("host isn't proxied", 0) end
        State.Proxied[host] = nil
    end
    function API:BlockUrl(url)     State.Blocked[url] = true  end
    function API:WhitelistUrl(url) State.Blocked[url] = false end

    function API:Enable()  State.Enabled = true  end
    function API:Disable() State.Enabled = false end
    function API:SetOption(name, value) State.Options[name] = value end

    State.API = API

    -- PUBLISH LAST: only now is the engine considered installed.
    GENV._G[KEY]    = State
    GENV._G.HttpSpy = API
    pconsole(format("[HttpSpy+Spoofer %s] Engine installed. Hooks are live.\n", State.Version))
end

--=============================================================================
-- 2. LIVE CONFIG (runs every execution)
--=============================================================================
local State = GENV._G[KEY]

if type(passedOptions) == "table" then
    for k, v in pairs(passedOptions) do State.Options[k] = v end
    if State.Serializer and passedOptions.Highlighting ~= nil then
        pcall(State.Serializer.UpdateConfig, { highlighting = passedOptions.Highlighting })
    end
end

-- Reset rules so edits/removals take effect on re-run.
-- (Change to `State.Spoofs = State.Spoofs or {}` if you want runtime spoofs
--  added via API:AddSpoof to survive loader re-runs.)
State.Spoofs = {}

-----------------------------------------------------------------------------
-- ACTIVE SPOOF RULES  (key = URL substring, value = table or function(req))
-----------------------------------------------------------------------------
State.Spoofs["example"] = {
    StatusCode = 200,
    Success    = true,
    Body       = "data",
}
-----------------------------------------------------------------------------

State.Printf("[HttpSpy+Spoofer] Config refreshed.\n\n")

return State.API
