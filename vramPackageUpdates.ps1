$hosts 		= import-csv .\HOSTS_DUMP_FROM_ACAS.csv
$findings 	= import-csv .\FINDINGS_DUMP_FROM_ACAS_NO_INFO.csv
$iavm 		= [xml](gc .\BASELINE_EXPORT_FROM_VRAM_PER_PACKAGE.xml)

$iavm.selectNodes("//Directive[./AssetType/Compliance/compliance_value!=2]/AssetType/Compliance") | % { $_.compliance_value = '2';}
$iavm.selectNodes("//Directive/AssetType/Compliance") | % {
	if($_.acknowledge_date -ne $null){
		$_.mitigation_date = $_.acknowledge_date;
	}else{
		$_.mitigation_date = (get-date -format "yyyy/MM/dd").toString()
	}
	
	$_.compliance_value = '2';
	$_.explanation = 'This requirement has been remediated via patches, policies and configuration settings.  Security posture is reflected in current ACAS Scans.';
	$_.mitigation_detail = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.  The systems are also maintained via polices and patches.'
	$_.justification = 'This requirement is satsified via patches, policies and configuration settings.';
}

$iavm.selectNodes("//Directive") | sort Name -descending | % {
	$iava = $_
	write-host "iava: $($iava.name)"
	$findings | ? { $_.'cross references' -like "*$($iava.name)*" } | select 'ip address', 'cross references' | % {
		$finding = $_
		$hosts | ? { $_.'IP Address' -eq $finding.'IP Address' } | % {
			$h = $_
			if($h.'OS CPE' -like '*windows*'){
				write-host "Windows", $h.'IP Address', $h.'OS CPE'
				$iava.selectNodes("//Directive[@name='$($iava.name)']/AssetType[@name='Windows']/Compliance") | %{
					$_.compliance_value = '4';
					$_.explanation = 'This requirement has not been implemented at this point in time due to mission needs and resource limitations.';
					$_.mitigation_detail = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.'
					$_.justification = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.';
				}
			}elseif($h.'OS CPE' -like '*linux*'){
				write-host "Linux", $h.'IP Address', $h.'OS CPE'
				$iava.selectNodes("//Directive[@name='$($iava.name)']/AssetType[@name='Linux']/Compliance") | %{
					$_.compliance_value = '4';
					$_.explanation = 'This requirement has not been implemented at this point in time due to mission needs and resource limitations.';
					$_.mitigation_detail = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.'
					$_.justification = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.';
				}
			}else{
				write-host "Other", $h.'IP Address', $h.'OS CPE'
				$iava.selectNodes("//Directive[@name='$($iava.name)']/AssetType[@name='Windows']/Compliance") | %{
					$_.compliance_value = '4';
					$_.explanation = 'This requirement has not been implemented at this point in time due to mission needs and resource limitations.';
					$_.mitigation_detail = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.'
					$_.justification = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.';
				}
			}
			
			write-host "overall:", $h.'IP Address', $h.'OS CPE'
			$iava.selectNodes("//Directive[@name='$($iava.name)']/AssetType[@name='overall']/Compliance") | %{
				$_.compliance_value = '4';
				$_.explanation = 'This requirement has not been implemented at this point in time due to mission needs and resource limitations.';
				$_.mitigation_detail = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.'
				$_.justification = 'The systems in this package are protected via network security, system hardenning, industry best practices and technical staff capabilities.';
			}
		}
	}
}

$iavm.save("VRAM_PACKAGE_UPDATE.xml")
