<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Search</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Search</h2>
</%block>
    

<%block name="content_main">
    % if not ResultsPage:
        Search only displays results off other pages.
    % endif
</%block>
