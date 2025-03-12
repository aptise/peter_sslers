<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Settings</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Configuration Settings</h2>
</%block>


<%block name="content_main">

    <div class="alert alert-info" role="alert">
      <h4>QuickStart</h4>
      <p>Settings are enabled in either the Application or the Configuration file.</p>
      
      <p>
        For initial setup, you should
        <ul>
            <li>Create New, or Select Existing, <a href="${admin_prefix}/acme-accounts">AcmeAccounts</a> for the Global Default and Global Backup roles.
                </li>
        </ul>
      </p>
      
    </div>


    <h3>Runtime Settings</h3>
    <p>
        These settings can be edited using the web interface
    </p>
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>SystemConfiguration</th>
                        <th>Link</th>
                        <th>Configured?</th>
                    <tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Global</th>
                        <td>
                            <a href="${admin_prefix}/system-configuration/${SystemConfiguration_global.slug}" class="label label-info">
                                SystemConfiguration-${SystemConfiguration_global.slug}
                            </a>
                        </td>
                        <td>
                            % if SystemConfiguration_global.is_configured:
                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Autocert</th>
                        <td>
                            <a href="${admin_prefix}/system-configuration/${SystemConfiguration_autocert.slug}" class="label label-info">
                                SystemConfiguration-${SystemConfiguration_autocert.slug}
                            </a>
                        </td>
                        <td>
                            % if SystemConfiguration_autocert.is_configured:
                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Certificate-If-Needed</th>
                        <td>
                            <a href="${admin_prefix}/system-configuration/${SystemConfiguration_cin.slug}" class="label label-info">
                                SystemConfiguration-${SystemConfiguration_cin.slug}
                            </a>
                        </td>
                        <td>
                            % if SystemConfiguration_cin.is_configured:
                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <h3>Environment Settings</h3>
    <p>
        These settings can be edited with your <code>environment.ini</code> file.
    </p>
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                % for section in sorted(documentation_grid.keys()):
                    <tr>
                        <th colspan="2">
                            ${section}
                        </th>
                    </tr>
                    % if '.section_requires' in documentation_grid[section]:
                        <tr>
                            <td colspan="2">
                                This section requires <code>${documentation_grid[section]['.section_requires']}</code>
                            </td>
                        </tr>
                    % endif
                    % for option in sorted(documentation_grid[section].keys()):
                        <% if option == '.section_requires': continue %>
                        <tr>
                            <th>${option}</th>
                            <td>
                                ${documentation_grid[section][option].get('docstring')}
                                % if documentation_grid[section][option].get('default'):
                                    <% _default = documentation_grid[section][option].get('default') %>
                                    <hr/>
                                    Default:
                                    % if _default[0] == '`':
                                        <code>${_default[1:-1]}</code>
                                    % else:
                                        ${_default}
                                    % endif
                                % endif
                                % if documentation_grid[section][option].get('show_on_settings'):
                                    <hr/>
                                    Active: <code>${request.api_context.application_settings.get(option) or ''}</code>
                                % endif
                            </thd>
                        </tr>
                    % endfor
                    <tr><td colspan="2">&nbsp;</td></tr>
                % endfor
            </table>
        </div>
    </div>
</%block>
