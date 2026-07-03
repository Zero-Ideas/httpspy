local HOOK_KEY = "__DynamicSpoofEngine"

if not shared[HOOK_KEY] then
    local original_request = (syn or http) and (syn or http).request or request
    assert(original_request, "No support for an HTTP request function!")

    -- Initialize global storage for our rules
    shared[HOOK_KEY] = {
        Original = original_request,
        Spoofs = {} -- This table holds your active spoof rules
    }

    -- Hook the request function using HttpSpy's async-yield architecture
    hookfunction(original_request, newcclosure(function(req, ...)
        if type(req) ~= "table" or type(req.Url) ~= "string" then
            return shared[HOOK_KEY].Original(req, ...)
        end

        local current_thread = coroutine.running()
        
        coroutine.wrap(function()
            -- Check if we have a spoof rule set up for this specific URL or domain
            local spoof_rule = nil
            for target_url, modifier in pairs(shared[HOOK_KEY].Spoofs) do
                if req.Url:find(target_url) then
                    spoof_rule = modifier
                    break
                end
            end

            -- If a rule exists, process it
            if spoof_rule then
                if type(spoof_rule) == "function" then
                    -- Dynamic Spoof: Pass request to a function to generate a fake response
                    local success, fake_response = pcall(spoof_rule, req)
                    if success and fake_response then
                        return coroutine.resume(current_thread, fake_response)
                    end
                elseif type(spoof_rule) == "table" then
                    -- Static Spoof: Instantly return a pre-defined response table
                    return coroutine.resume(current_thread, spoof_rule)
                end
            end

            -- If no spoof rules matched, let the real request happen naturally
            local success, real_response = pcall(shared[HOOK_KEY].Original, req)
            if not success then
                error(real_response, 0)
            end

            return coroutine.resume(current_thread, real_response)
        end)()

        return coroutine.yield()
    end))

    if request then replaceclosure(request, original_request) end
    print("[Engine Ready] Permanent asynchronous spoof engine injected.")
end

-- =============================================================================
-- 2. YOUR ACTIVE SPOOF RULES (Re-run this part to instantly update rules)
-- =============================================================================

-- Reset rules on re-run so old rules don't linger
shared[HOOK_KEY].Spoofs = {}
shared[HOOK_KEY].Spoofs["example"] = function(request_data)
    
    return {
        StatusCode = 200,
		Success = true,
        Body = 'data',
    }
end

print("[Engine Updated] Active spoof configurations refreshed.")