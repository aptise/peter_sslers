<!DOCTYPE html>.
<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>SSL Certificate Administration</title>

<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="${admin_prefix}/static/bootstrap-3.3.6/bootstrap.min.css" >

<!-- Optional theme -->
<link rel="stylesheet" href="${admin_prefix}/static/bootstrap-3.3.6/bootstrap-theme.min.css" >

<style type="text/css">
    timestamp {font-size: .8em;
               font-family: Menlo,Monaco,Consolas,"Courier New",monospace;
               }
    samp {background-color: #EEE;
          padding: 3px;
          font-size: .9em;
          }
    code.payload {font-size: .7em;
                  padding: 2px;
                  color: #337ab7;
                  }
    tr.success {border-left: 2px solid green;
                }
    .nav>li>a{padding:5px 10px;}
</style>

</head>
<body>
<div class="container">

    <%block name="breadcrumb">
        <ol class="breadcrumb">
            ${request.breadcrumb_prefix|n}
            <li class="active">Admin</li>
        </ol>
    </%block>

    <%block name="page_header">
        <div class="row">
            <div class="col-sm-6">
                <%block name="page_header_col">
                    <h2>Page Header</h2>
                </%block>
            </div>
            <div class="col-sm-6"><%block name="page_header_nav"></%block></div>
        </div>
    </%block>

    <%block name="content_main">
        main content
    </%block>

    ${next.body()}

    <%block name="footer">
        <ol class="breadcrumb" style="margin-top: 20px;">
            <li><timestamp>${request.api_context.timestamp.isoformat()|n}</timestamp></li>
        </ol>
    </%block>

</div>
</body>
</html>