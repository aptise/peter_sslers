<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/certificates">Certificates</a></li>
        <li><a href="/.well-known/admin/certificates/${LetsencryptServerCertificate.id}">Focus [${LetsencryptServerCertificate.id}]</a></li>
        <li class="active">Renew</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate - Focus - RENEW</h2>
</%block>
    

<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <form method="POST"
                  action="/.well-known/admin/certificate/${LetsencryptServerCertificate.id}/renew/custom"
                  enctype="multipart/form-data"
            >
                <h3>Custom Renewal</h3>
        
                <p>We will generate a new CSR through letsencypt</p>
        
                <table class="table table-striped table-condensed">
                    <tr>
                        <th>renewal of: id</th>
                        <td>
                            <span class="label label-default">${LetsencryptServerCertificate.id}</span>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: issued</th>
                        <td>
                            <timestamp>${LetsencryptServerCertificate.timestamp_signed}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${LetsencryptServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${LetsencryptServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td>${LetsencryptServerCertificate.domains_as_string}</td>
                    </tr>
                    <tr>
                        <th>Lets Encrypt Account</th>
                        <td>
                            % if LetsencryptServerCertificate.letsencrypt_account_key_id:
                                <div class="radio">
                                    <label>
                                        <input type="radio" name="account_key_option" id="account_key_option-existing" value="existing" checked="checked">
                                        Use existing Account Key 
                                    </label>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/account-keys/${LetsencryptServerCertificate.letsencrypt_account_key_id}"
                                    >
                                        &gt; ${LetsencryptServerCertificate.letsencrypt_account_key_id}
                                    </a>
                                </div>
                                <div class="radio">
                                    <label>
                                        <input type="radio" name="account_key_option" id="account_key_option-upload" value="upload">
                                        Upload new Account Key
                                    </label>
                                </div>
                            % else:
                                <input type="hidden" name="account_key_option" id="account_key_option-upload" value="upload">
                            % endif

                            ${admin_partials.formgroup__account_key_file(show_text=False)}
                
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key</th>
                        <td>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="private_key_option" id="private_key_option-existing" value="existing" checked>
                                    Use existing RSA Key
                                </label>
                            </div>
                            <div class="radio">
                                <label>
                                    <input type="radio" name="private_key_option" id="private_key_option-upload" value="upload">
                                    Upload new RSA Key
                                </label>
                            </div>

                            ${admin_partials.formgroup__private_key_file(show_text=False)}

                        </td>
                    </tr>
                </table>
        
                <input type="submit" value="submit" />
        
            </form>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-6">
        </div>
    </div>

</%block>
