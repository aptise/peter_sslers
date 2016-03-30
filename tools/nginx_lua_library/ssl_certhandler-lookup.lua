local ssl_certhandler = require "ssl_certhandler"

-- Local cache related
local cert_cache = ngx.shared.cert_cache
local cert_cache_duration = 7200 -- 2 hours

local prime_version = 1
ssl_certhandler.set_ssl_certificate(cert_cache, cert_cache_duration, prime_version)

return
