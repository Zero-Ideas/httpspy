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
