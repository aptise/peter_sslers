                    <div class="form-group">
                        <label for="f1-csr_text">CSR Text</label>
                        <textarea class="form-control" rows="3" name="csr_text" id="f1-csr_text"></textarea>
                        <p class="help-block">
                            Enter the contents of a CSR request signed by a Private Key
                        </p>
                    </div>


                <h3>Create a Certificate Signing Request (CSR)</h3>
                    <h4>for a single domain</h4>
                    <p>
                        <code>openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr</code>
                    </p>
                    <h4>for multiple domains</h4>
                    <p>
                        <code>openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com")) > domain.csr</code>
                    </p>
                    <p>on a mac using homebrew?</p>
                    <p>
                        <code>/usr/local/opt/openssl/bin/openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /usr/local/etc/openssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com")) > domain_multi.csr</code>
                    </p>
