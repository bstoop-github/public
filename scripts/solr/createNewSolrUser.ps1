$user = "solr"
$pass = "SolrRocks"
 
$solrUrl = "http://hostname:8983"
 
$secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
  
Invoke-WebRequest -Uri $solrUrl/solr/admin/authentication `
    -UseBasicParsing `
    -Method "POST" `
    -ContentType "application/json" `
    -Body '{"set-user":{"newuser": "password"}}' `
    -Credential $credential