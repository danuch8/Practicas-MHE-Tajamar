$localip = (Get-NetIPAddress -InterfaceAlias "Ethernet0").IPAddress

if($locaip -ne "192.168.120.23"){
    $updateip = $localip.split(".")
    $updateip[3] = "97"
    $updateip = [String]::Join(".",$updateip)
    ipconfig /flushdns
    ipconfig /registerdns
    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses ($updateip)
}else{
    ipconfig /flushdns
    ipconfig /registerdns
}
