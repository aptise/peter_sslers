local ssl_certhandler = require "ssl_certhandler"

-- Local cache related
local cert_cache = ngx.shared.cert_cache

ssl_certhandler.expire_ssl_certs(cert_cache)