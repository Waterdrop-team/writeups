<?php if(!class_exists("View", false)) exit("no direct access allowed");?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>blog</title>

<link href="/css/bootstrap.min.css" rel="stylesheet">
<link href="/css/style.css" rel="stylesheet">
<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
</head>
<body>
<div class="container">
<?php include $_view_obj->compile($__template_file); ?>
</div>
</body>
<script src="/js/main.js"></script>
</html>