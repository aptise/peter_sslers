<html>
<head>

<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">

<!-- Optional theme -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap-theme.min.css" integrity="sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r" crossorigin="anonymous">

<!-- Latest compiled and minified JavaScript -->
## <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>

<style type="text/css">
    timestamp {font-size: .8em;
               font-family: Menlo,Monaco,Consolas,"Courier New",monospace;
               }
    samp {background-color: #EEE;
          padding: 3px;
          font-size: .9em;
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