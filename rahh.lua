loadstring(game:HttpGet("https://api.jnkie.com/api/v1/luascripts/public/86b678525ebc850ba62a55acd2e92ceddc86cb15dee91b28a2d916854f1b4865/download"))()
_G.HttpSpy = loadstring(game:HttpGet("https://raw.githubusercontent.com/Zero-Ideas/httpspy/refs/heads/main/spy_spoof.lua"))()

_G.HttpSpy:SetSpoof("httpbin%.org/get", function(requestData)
    return {
        StatusCode = 200,
        Success = true,
        Body = '{"valid":true,"error":null}',
    }
end)
-- Target script for testing HttpSpy interception (hooking + spoofing).
-- Run merged.lua (with your hook/spoof set up) FIRST, then run this.

local reqfunc = (syn or http).request;

local response = reqfunc({
    Url = "https://httpbin.org/get",
    Method = "GET",
});

print("StatusCode:", response.StatusCode);
print("Success:", response.Success);
print("Body:", response.Body);
