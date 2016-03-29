<html>
<head>

<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="/.well-known/admin/static/bootstrap-3.3.6/bootstrap.min.css" >

<!-- Optional theme -->
<link rel="stylesheet" href="/.well-known/admin/static/bootstrap-3.3.6/bootstrap-theme.min.css" >

<style type="text/css">
    timestamp {font-size: .8em;
               font-family: Menlo,Monaco,Consolas,"Courier New",monospace;
               }
    samp {background-color: #EEE;
          padding: 3px;
          font-size: .9em;
          }
    tr.success {border-left: 2px solid green;
                }
</style>

<title>
SSL Certificate Administration
</title>

</head>
<body>
<div class="container">

    <%block name="breadcrumb">
        <ol class="breadcrumb">
            <li>${request.active_domain_name}</li>
            <li class="active">Admin</li>
        </ol>
    </%block>

    <%block name="page_header">
        <h2>Page Header</h2>
    </%block>

    <%block name="content_main">
        main content
    </%block>

    ${next.body()}

</div>
</body>
</html>