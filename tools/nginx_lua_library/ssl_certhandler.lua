local redis = require "resty.redis"
local ssl = require "ngx.ssl"

-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
-- START: these are just some helper functions


function get_redcon()
	-- this sets up our redis connection
	-- it checks to see if it is a pooled connection (ie, reused) and changes to db9 if it is new
	-- Setup Redis connection
	local redcon = redis:new()
	-- Connect to redis.  NOTE: this is a pooled connection
	local ok, err = redcon:connect("127.0.0.1", "6379")
	if not ok then
		ngx.log(ngx.ERR, "REDIS: Failed to connect to redis: ", err)
		return nil, err
	end
	-- Change the redis DB to #9
	-- We only have to do this on new connections
	local times, err = redcon:get_reused_times()
	if times <= 0 then
		ngx.log(ngx.ERR, "changing to db 9: ", times)
		redcon:select(9)
	end
	return redcon
end


function redis_keepalive(redcon)
	-- put `redcode` into the connection pool
	-- * pool size = 100
	-- * idle time = 10s
	-- note: this will close the connection
	local ok, err = redcon:set_keepalive(10000, 100)
	if not ok then
		ngx.log(ngx.ERR, "failed to set keepalive: ", err)
		return
	end
end


function prime_1__query_redis(redcon, _server_name)
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = "d:" .. _server_name
    local domain_data, err = redcon:hmget(key_domain, 'c', 'p', 'i')
    if domain_data == nil then
        ngx.log(ngx.ERR, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end
    if domain_data == ngx.null then
        ngx.log(ngx.ERR, "`ngx.null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
	end    
	-- ngx.log(ngx.ERR, 'err ', err)
	-- ngx.log(ngx.ERR, 'domain_data ', tostring(domain_data))

	-- lua arrays are 1 based!
	local id_cert = domain_data[1]
	local id_pkey = domain_data[2]
	local id_cacert = domain_data[3]

    ngx.log(ngx.DEBUG, "id_cert ", id_cert)
    ngx.log(ngx.DEBUG, "id_pkey ", id_pkey)
    ngx.log(ngx.DEBUG, "id_cacert ", id_cacert)
	
	if id_cert == ngx.null or id_pkey == ngx.null or id_cacert == ngx.null then
        ngx.log(ngx.ERR, "`id_cert == ngx.null or id_pkey == ngx.null or id_cacert == ngx.null for domain(", key_domain, ")")
        return nil, nil
	end
	
	local pkey, err = redcon:get('p'..id_pkey)
    if pkey == nil then
        ngx.log(ngx.ERR, "failed to retreive pkey (", id_pkey, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end

	local cert, err = redcon:get('c'..id_cert)
    if cert == nil or cert == ngx.null then
        ngx.log(ngx.ERR, "failed to retreive certificate (", id_cert, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end

	local cacert, err = redcon:get('i'..id_cacert)
    if cacert == nil or cacert == ngx.null then
        ngx.log(ngx.ERR, "failed to retreive ca certificate (", id_cacert, ") for domain (", key_domain, ") Err: ", err)
        return nil, nil
    end
    
    local fullchain = cert.."\n"..cacert
	return fullchain, pkey
end


function prime_2__query_redis(redcon, _server_name)
    -- If the cert isn't in the cache, attept to retrieve from Redis
    local key_domain = _server_name
    local domain_data, err = redcon:hmget(key_domain, 'p', 'f')
    if domain_data == nil then
        ngx.log(ngx.ERR, "`nil` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
    end
    if domain_data == ngx.null then
        ngx.log(ngx.ERR, "`ngx.null` failed to retreive certificates for domain(", key_domain, ") Err: ", err)
        return nil, nil
	end    

	local pkey = domain_data[1]
	local fullchain = domain_data[2]

	if pkey == ngx.null or fullchain == ngx.null then
        ngx.log(ngx.ERR, "`pkey == ngx.null or fullchain == ngx.null for domain(", key_domain, ")")
        return nil, nil
	end
	
	return fullchain, pkey
end


-- END helper functions
-- ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~

-- =============================================================================

-- START MAIN LOGIC


function set_ssl_certificate(_cert_cache, _cert_cache_duration, prime_method)

	local server_name = ssl.server_name()

	-- local request debug
	if false then
		ngx.log(ngx.NOTICE, "===========================================================")
		ngx.log(ngx.NOTICE, server_name)
	end

	-- Check for SNI request.
	if server_name == nil then
		ngx.log(ngx.NOTICE, "SNI Not present - performing IP lookup")
	
		-- don't bother with IP lookups
		-- exit out and just fall back on the default ssl cert
		return
	end 

	-- Check cache for certficate
	local cert = _cert_cache:get(server_name .. ":c")
	local key = _cert_cache:get(server_name .. ":k")
	if cert ~= nil and key ~= nil then
		ngx.log(ngx.ERR, "Cert cache HIT for: ", server_name)
	
		if cert == 'x' or key == 'x' then
			ngx.log(ngx.NOTICE, "Previously seen unsupported domain")
	
			-- don't bother with IP lookups
			-- exit out and just fall back on the default ssl cert
			return
		end
	
	else
		ngx.log(ngx.ERR, "Cert cache MISS for: ", server_name)
		-- ok, try to get it from redis

		-- grab redis connection
		local redcon, err = get_redcon()
		if redcon == nil then
			-- exit out and just fall back on the default ssl cert
			return
		end
	
		-- actually query redis
		if prime_method == 1 then
			cert, key = prime_1__query_redis(redcon, server_name)
		elseif prime_method == 2 then
			cert, key = prime_2__query_redis(redcon, server_name)
		else
			ngx.log(ngx.ERR, "invalid `prime_method` not (1, 2) is `", prime_method)
			-- don't bother with IP lookups
			-- exit out and just fall back on the default ssl cert
			return
		end

		-- eventually use a fallback search here
		-- but we can't do that yet
		if cert ~= nil and key ~= nil then 
	
			-- convert from PEM to der
			cert = ssl.cert_pem_to_der(cert)
			key = ssl.priv_key_pem_to_der(key)
	
			-- Add key and cert to the cache 
			local success, err, forcible = _cert_cache:set(server_name .. ":c", cert, _cert_cache_duration)
			ngx.log(ngx.DEBUG, "Caching Result: ", success, " Err: ",  err)

			local success, err, forcible = _cert_cache:set(server_name .. ":k", key, _cert_cache_duration)
			ngx.log(ngx.DEBUG, "Caching Result: ", success, " Err: ",  err)

			ngx.log(ngx.DEBUG, "Cert and key retrieved and cached for: ", server_name)

			-- return the redcon to the connection pool
			redis_keepalive(redcon)
		else     
			ngx.log(ngx.ERR, "Failed to retrieve " .. (cert and "" or "cert ") ..  (key and "" or "key "), "for ", server_name)

			-- set a fail marker
			local success, err, forcible = _cert_cache:set(server_name .. ":c", 'x', _cert_cache_duration)
			local success, err, forcible = _cert_cache:set(server_name .. ":k", 'x', _cert_cache_duration)
		
			-- return the redcon to the connection pool
			redis_keepalive(redcon)

			-- exit out and just fall back on the default ssl cert
			return
		end
	end

	-- since we have a server name, now we can continue...
	ssl.clear_certs()

	-- Set cert
	local ok, err = ssl.set_der_cert(cert)
	if not ok then
		ngx.log(ngx.ERR, "failed to set DER cert: ", err)
		return
	end

	-- Set key
	local ok, err = ssl.set_der_priv_key(key)
	if not ok then
		ngx.log(ngx.ERR, "failed to set DER key: ", err)
		return
	end
end


function expire_ssl_certs(_cert_cache)
	ngx.header.content_type = 'text/plain'
	local prefix = ngx.var.location
	if ngx.var.request_uri == prefix..'/all' then
		_cert_cache:flush_all()
		ngx.say('{"result": "success", "expired": "all"}')
		return
	end
	local _domain = string.match(ngx.var.request_uri, '^'..prefix..'/domain/([%w-.]+)$')  
	if _domain then
		_cert_cache:delete(_domain)
		ngx.say('{"result": "success", "expired": "domain", "domain": "' .. _domain ..'"}')
		return
	end
	ngx.say('{"result": "error", "expired": "None", "reason": "Unknown URI"}')
	ngx.status = 404
	return
end


local _M = {get_redcon = get_redcon,
			redis_keepalive = redis_keepalive,
			prime_1__query_redis = prime_1__query_redis,
			prime_2__query_redis = prime_2__query_redis,
			set_ssl_certificate = set_ssl_certificate,
			expire_ssl_certs = expire_ssl_certs,
			}

return _M