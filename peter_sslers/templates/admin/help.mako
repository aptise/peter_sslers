<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Help</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Admin Help</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
        
            <h3>What must be installed on my webserver?</h3>
            <p>
                Your webserver must have the following 3 items installed:
                <ul>
                    <li>PrivateKey</li>
                    <li>ServerCertificate</li>
                    <li>CACertificate</li>
                </ul>
                Some webservers require the ServerCertificate and CACertificate be joined in PEM format as a "fullchain" certificate.
            </p>
            
        
            
        </div>
        <div class="col-sm-6">
            
            <p>Most pages have documentation on them</p>
            
            <h4>Core Objects</h4>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>AccountKey</th>
                    <td>An RSA Key that is registered with the LetsEncrypt service.
                        The <em>AccountKey</em> is only used for Authorization with the LetsEncrypt service.
                    </td>
                </tr>
                <tr>
                    <th>PrivateKey</th>
                    <td>An RSA Key that is used to sign <em>CertficateRequest</em>s AND is paired to your <em>ServerCertificate</em>.
                        The <em>PrivateKey</em> must be installed on your webserver to serve https content.
                    </td>
                </tr>
                <tr>
                    <th>CertificateRequest</th>
                    <td>In order to get a <em>ServerCertificate</em> you create a <em>CertificateRequest</em> and sign it with your <em>PrivateKey</em>.
                        It is generally not needed after a <em>ServerCertificate</em> is issued.
                    </td>
                </tr>
                <tr>
                    <th>ServerCertificate</th>
                    <td>Your <em>ServerCertificate</em> is an OpenSSL certificate that has been signed by a trusted <em>CACertificate</em>. 
                        The <em>ServerCertificate</em> must be installed on your webserver with the <em>PrivateKey</em> that signed the corresponding <em>CertificateRequest</em> to serve https content.
                    </td>
                </tr>
                <tr>
                    <th>CACertificate</th>
                    <td>A trusted Certificate Authority Certificate, used to sign your <em>ServerCertificate<em>.
                        It must be installed on your webserver in order to serve https content.
                    </td>
                </tr>
                
            </table>
            
        </div>
    </div>
</%block>
