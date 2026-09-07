#Requires -Version 5.1
<#
.SYNOPSIS
    Prints the team roster and login tokens from the hunt store.
.DESCRIPTION
    The server prints these on start; this reads them back without a restart,
    for when somebody loses theirs.
.EXAMPLE
    .\Show-Tokens.ps1
#>
[CmdletBinding()]
param([string]$Db = (Join-Path (Split-Path -Parent $PSScriptRoot) 'data\hunt.db'))
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Db)) { throw "No store at $Db. Start the server once first." }
& node -e "
const {DatabaseSync}=require('node:sqlite');
const db=new DatabaseSync(process.argv[1]);
const order={Command:0,Bravo:1,Alpha:2};
const rows=db.prepare('select name,role,team,token from members').all()
  .sort((a,b)=>(order[a.team]??9)-(order[b.team]??9)||a.name.localeCompare(b.name));
let team=null;
for (const r of rows){ if(r.team!==team){team=r.team;console.log('\n  '+team);} 
  console.log('    '+r.token+'   '+r.name.padEnd(9)+' '+r.role); }
console.log('');
" $Db
