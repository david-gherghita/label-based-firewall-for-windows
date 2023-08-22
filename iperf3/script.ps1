$interfaceAlias = "Ethernet"

$iperfServer = "192.168.0.118"
$iperfPort = "5201"

$iperfPath = ".\iperf3.exe"
$outputFile = "iperf_results.txt"

for ($mtu = 70; $mtu -le 1500; $mtu += 10) {
    for ($i = 0; $i -lt 5; $i++) {
        netsh interface ipv4 set subinterface "$interfaceAlias" mtu=$mtu store=persistent

        $iperfOutput = & $iperfPath -c $iperfServer -p $iperfPort -f m -i 10
        $iperfOutput | Out-File -Append -FilePath $outputFile -Encoding UTF8
    }
}
