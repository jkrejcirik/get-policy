# Rule parser v0.5, Jan Krejcirik 4/2020

<#

.DESCRIPTION
The script extract some configurations from Fortinet configuration file.

.EXAMPLE
get-policy.ps1 -ConfigFile ./fortinet-file.conf -Type ServiceGroup

.EXAMPLE
get-policy.ps1 -ConfigFile ./fortinet-file.conf

.NOTES
Tested with Firewall Fortinet 500E

#>

Param([String]$ConfigFile,
      [ValidateSet('Address','AddressGroups','Policy','ServiceCategory','CustomService',
                   'ServiceGroup','TrafficShaper','StaticRoute')]
      [String]$Type
)

class CColumn {
    [String] $Name         # Column name
    [String] $Key          # Column identifikator
}

# get value from row by key
function Get-Value {
  Param ([String]$row,[String]$key)
  if ($row.Trim().StartsWith($key)){ 
    return $row.Substring($row.Indexof($key)+$key.Length + 1).Replace('" "', " | ")
  }
}

class FWConfig {
  [bool]   $Policy = $false  # policy  definition attribute
  [bool]   $Rule = $false    # rule definition attribute
  [String] $ConfigFile     # Path to Fortinet config file
  [String] $Type           # type of converted data 'Addresses','AddressGroups','Policy','ServiceCategory',...
  [String] $Header         # The first row, columns names
  [String] $TypeKey        # Begin of valid data identificator
  [String] $OutBuffer      # Buffer for assembly row
  [system.collections.generic.list[CColumn]] $Columns  # List of columns definition
  [system.collections.generic.list[String]]  $Values   # List of values
  
  AddColumn($N,$K){   # Add one column definition
    $col = New-Object CColumn
    $col.Name = $N; $col.Key = $K; 
    $this.Columns.Add($col)
  }

  InitValues() {      # initize list of values
    $this.Values.Clear();
    for($i=0; $i -lt $this.Columns.Count ; $i++){
        $this.Values.Add("")  
    }
  }

  WriteHeader() {     # Write the first line of table
    Write-Host '"' -NoNewline; Write-Host $this.Columns.Name[0] -NoNewline; Write-Host '"' -NoNewline
    for($i=1; $i -lt $this.Columns.Count ; $i++){
        Write-Host ';"' -noNewline; Write-Host $this.Columns.Name[$i] -NoNewline; Write-Host '"' -NoNewline
    }
    Write-Host
  }

  FWConfig($ConfigFile,$Type){   # Constructor
    $this.Type = $Type
    $this.ConfigFile = $ConfigFile
    $this.Columns = [system.collections.generic.list[CColumn]]::new()
    $this.Values  = [system.collections.generic.list[String]]::new()
  
  # Main process
  
    switch ($Type) {
        "StaticRoute" {
        # Firewall Static route
        $this.TypeKey = "config router static"
        $this.AddColumn("Id","edit")
        $this.AddColumn("Destination","set dst")
        $this.AddColumn("Gateway","set gateway")
        $this.AddColumn("Device","set device")
        $this.AddColumn("Comment","set comment")
        break
        }
        "TrafficShaper" {
        # Firewall Traffic shaper
        $this.TypeKey = "config firewall shaper traffic-shaper"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Maximum bandwidth","set maximum-bandwidth")
        $this.AddColumn("Guaranteed bandwidth","set guaranteed-bandwidth")
        $this.AddColumn("Per policy","set per-policy")
        break
        }
        "ServiceGroup" {
        # Firwall Service group
        $this.TypeKey = "config firewall service group"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Member","set member")
        $this.AddColumn("Comment","set comment")
        break
        }
        "CustomService" {
        # Firewall Custom service 
        $this.TypeKey = "config firewall service custom"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Category","set category")
        $this.AddColumn("Protocol","set protocol")
        $this.AddColumn("TCP Portrange","set tcp-portrange")
        $this.AddColumn("UDP Portrange","set udp-portrange")
        $this.AddColumn("Protocol Number","set protocol-number")
        $this.AddColumn("ICMP Type","set icmptype")
        break
        }     
        "ServiceCategory" {
        # Firewall service category
        $this.TypeKey = "config firewall service category"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Comment","set comment")
        break
        }     
        "AddressGroup" {
        # Firewall address groups definition
        $this.TypeKey = "config firewall addrgrp"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Members","set member")
        break 
        }
        "Address" {
        # Firewall addresses definition    
        $this.TypeKey = "config firewall address"
        $this.AddColumn("Name","edit")
        $this.AddColumn("Type","set type")
        $this.AddColumn("Subnet","set subnet")
        $this.AddColumn("Start-IP","set start-ip")
        $this.AddColumn("End-IP","set end-ip")
        $this.AddColumn("FQDN","set fqdn")
        $this.AddColumn("Associated-interface","set associated-interface")
        $this.AddColumn("Comment","set comment")
        break 
        }
        default { 
        # include Policy, Firewall policy rules
        $this.TypeKey = "config firewall policy"
        $this.AddColumn("Id","edit")
        $this.AddColumn("Name","set name")
        $this.AddColumn("Source interface","set srcintf")
        $this.AddColumn("Destination interface","set dstintf")
        $this.AddColumn("Source address","set srcaddr")
        $this.AddColumn("Destination address","set dstaddr")
        $this.AddColumn("Action","set action")
        $this.AddColumn("Service","set service")
        };  
    }   

    foreach($line in Get-Content $this.ConfigFile) {
      if ($line -contains $this.TypeKey){ 
        $this.WriteHeader() #  Write-Host $this.Header
        $this.Policy=$true; continue 
      }
      if ($this.Policy -and $line.Trim().StartsWith("end")){ 
        $this.Policy = $false; $this.Rule = $false; continue 
      }
      if ($this.Policy -and $line.Trim().StartsWith("edit")){
        $this.InitValues()  # clear & initize list of values
        $this.Values[0] = Get-Value -row $line -key "edit"
        $this.Rule = $true; continue 
      }
      if ($this.Policy -and $this.Rule) {
        for($i=1; $i -lt $this.Columns.Count ; $i++){
            $tmp = Get-Value -row $line -key $this.Columns.Key[$i]
            if ($tmp.Length) { $this.Values[$i] = $tmp }
        }
        if ($line.Trim().StartsWith("next")){ 
            Write-Host ($this.Values[0]) -NoNewline
            for($i=1; $i -lt $this.Values.Count ; $i++){
                Write-Host ";" -NoNewline; Write-Host $this.Values[$i] -NoNewline
            } 
            Write-Host
            $this.Rule = $false; continue 
        }
      }
    }
  }
}


$data = [FWConfig]::new($ConfigFile,$Type)
 