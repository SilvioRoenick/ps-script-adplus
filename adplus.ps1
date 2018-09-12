Get-Content "$env:USERPROFILE\Desktop\users.csv" | Out-File "$env:USERPROFILE\Desktop\users_utf8.csv" -Encoding utf8
$users = Import-Csv -Path "$env:USERPROFILE\Desktop\users_utf8.csv" -Delimiter ";" -Encoding Unicode

$rootOU = "OU=Headquarter,DC=corp,DC=example,DC=com"

function Aufbereitung([String]$wert)
{
    $wert = $wert.Replace("ä","ae")
    $wert = $wert.Replace("ö","oe")
    $wert = $wert.Replace("ü","ue")
    return $wert
}

function OUTest([String]$ou)
{
    if(Get-ADOrganizationalUnit -Filter {distinguishedName -eq $ou})
        {return $true} else {return $false}
}

function AbteilungsStruktur([String]$abteilung)
{
    if(OUTest("OU=$abteilung,$rootOU"))
        {} else {New-ADOrganizationalUnit -Name $abteilung -Path  $rootou}

    "Benutzer","Computer","Gruppen" | % {
        if(OUTest("OU=$_,OU=$abteilung,$rootOU")){} else {New-ADOrganizationalUnit -Name $_ -Path "OU=$abteilung,$rootOU"}
    }
}

function GPOsStruktur([String]$abteilung)
{
    $abteilung
    New-GPO -Name "$abteilung-Allgemein" | New-GPLink -Target "OU=$abteilung,$rootOU"
}


foreach($user in $users)
{

    if(($user.Abteilung -eq $null) -or ($user.Abteilung -eq ""))
        {$abteilung = "Allgemein"} else {$abteilung = $user.Abteilung}

    AbteilungsStruktur($abteilung)
    GPOsStruktur($abteilung)
    $name = Aufbereitung($user.Name)
    $vorname = Aufbereitung($user.Vorname)

    $login= ($vorname.Substring(0,1) + "." +  $name).ToLower()

    Write-Output ""
    Write-Output "Bearbeite User: $login"
    Write-Output "Vorname: $vorname Nachname: $name"

if ((Get-ADUser -Filter { SamAccountName -eq $login }) -eq $Null)
{
    Write-Output "$login existiert nicht."

    #$password = "Pa$$w0rd" | ConvertTo-SecureString -AsPlainText -Force

    $param = @{
        Name = $login 
        AccountPassword = "Pa`$`$w0rd" | ConvertTo-SecureString -AsPlainText -Force
        GivenName = $vorname 
        Surname = $name 
        Initials = $($vorname.Substring(0,1) + $name.Substring(0,1)) 
        Path = "OU=Benutzer,OU=$abteilung,$rootOU"
        DisplayName = $($user.Vorname) + " " + $($user.Name)

        StreetAddress = (Get-ADOrganizationalUnit -Identity "OU=$abteilung,$rootOU").StreetAddress
        City = (Get-ADOrganizationalUnit -Identity "OU=$abteilung,$rootOU").City
        State = (Get-ADOrganizationalUnit -Identity "OU=$abteilung,$rootOU").State
        PostalCode = (Get-ADOrganizationalUnit -Identity "OU=$abteilung,$rootOU").PostalCode
        Country = (Get-ADOrganizationalUnit -Identity "OU=$abteilung,$rootOU").Country

        Enabled = $true
    }

    New-ADUser @param

}
else
{
    Write-Output "$login existiert!"
    Write-Output (Get-ADUser -Filter { SamAccountName -eq $login }).DistinguishedName

}

}



$abteilungsOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $rootOU -SearchScope 1

foreach($abteilungOU in $abteilungsOUs)
{
$benutzerOU = "OU=Benutzer,$($abteilungOU.DistinguishedName)"
$gruppenOU = "OU=Gruppen,$($abteilungOU.DistinguishedName)"

    $gruppenName = $abteilungOU.Name+"-Mitarbeiter"
    if((Get-ADGroup -Filter {Name -eq $gruppenName} )-eq $Null){ New-ADGroup -Name $gruppenName -GroupCategory 1 -GroupScope 1 -Path $gruppenOU }


if(OUTest($benutzerOU) -and OUTest($gruppenOU))
    {
    $adUsers = Get-ADUser -Filter { Name -Like "*" } -Searchbase $benutzerOU -Properties Description
    
    foreach($adUser in $adUsers)
        {
        Add-ADGroupMember -Identity $(Get-ADGroup -Identity "CN=$gruppenName,$gruppenOU") -Members $(Get-ADUser -Identity $adUser)
        }
    }

    ###

$abteilungsFreigabeGruppe = $abteilungOU.Name+"-AbteilungsFreigabe(Vollzugriff)"
if((Get-ADGroup -Filter {Name -eq $abteilungsFreigabeGruppe} )-eq $Null){ New-ADGroup -Name $abteilungsFreigabeGruppe -GroupCategory 1 -GroupScope 0 -Path $gruppenOU }

$abteilungsGruppe = Get-ADGroup -Filter "Name -Like '*$gruppenName*'" -Searchbase $gruppenOU -Properties *

Add-ADGroupMember -Identity $(Get-ADGroup -Identity "CN=$abteilungsFreigabeGruppe,$gruppenOU") -Members $(Get-ADGroup -Identity $abteilungsGruppe)

    $path = "C:\Shares\$($abteilungOU.Name)"


    If(!(Test-Path $path))
    {
        New-Item -ItemType Directory -Force -Path $path
        $acl = Get-ACL -Path $path
        $acl.SetAccessRuleProtection($true,$true)

        Set-Acl -Path $path -AclObject $acl
        $acl = Get-ACL -Path $path

        $acl.Access | ?{$_.IdentityReference -like '*\Benutzer'} | %{$acl.RemoveAccessRule($_)}
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule("$abteilungsFreigabeGruppe", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($ace)

        Set-Acl -Path $path -AclObject $acl
    }

    If(!(Get-SMBShare -Name $($abteilungOU.Name) -ErrorAction 0))
    {
        New-SmbShare -Name $($abteilungOU.Name) -Path C:\Shares\$($abteilungOU.Name) -FullAccess Jeder
    } 

}


