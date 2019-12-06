Function Invoke-All{

    <#

    .SYNOPSIS
        There were many instances where we pipe cmdlets and wait for the output for hours or days, 
        the commands simply takes so long just because of too many objects it has to process sequentially.
        This function uses runspaces to achieve multi-threading to run powershell commands.
        I have made the function very generic, easy-to-use and lightweight as possible.

        TODO:
            Handle Executables.
            Extend to capture the Error and Verbose outputs from the Job streams

    .DESCRIPTION
        Invoke-All is the function exported from the Module. It is a wrapper like function which takes input from Pipeline or using explicit parameter and process the command consequently using runspaces.
        I have mainly focused on Exchange On-Perm and Online Remote powershell (RPS) while developing the script. 
        Though I have only tested it with Exchange Remote sessions and Snap-ins, it can be used on any powershell cmdlet or function.

        Exchange remote powershell uses Implicit remoting, the Proxyfunctions used by the Remote session doesn’t accept value from pipeline.
        Therefore the Script requires you to declare all the Parameters that you want to use in the command. See examples on how to do it.

    .NOTES
        Version        : 2.4
        Author         : Santhosh Sethumadhavan (santhse@microsoft.com)
        Prerequisite   : Requires Powershell V3 or Higher.

        V 1.1  -  Try/Finally block fixes on the End block
        v 2.0  -  Some optimizations on the finally blocks.
                  Added support for External scripts.
        v 2.1  -  Added Batching support
        v 2.2  -  Optimized Job collection
		v 2.3  -  Added the ability to gracefully cancel the script between batches. Useful when jobs are stuck and not completing.
				  Enabled Strict Mode
        v 2.4  -  For the Powershell objects returned from Remote Runspace/Session to work properly, discover and add the TypeTables by default.
                  https://blogs.msdn.microsoft.com/b/powershell/archive/2010/01/07/how-objects-are-sent-to-and-from-remote-sessions.aspx  	
        v 2.5  -  Logs the errors from the Jobs

    .PARAMETER ScriptBlock
        Scriptblock to execute in parallel.
        Usually it is the 2nd Pipeline block, wrap your command as shown in the below examples and it should work fine.
        You cannot use alias or external scripts. If you are using a function from a custom script, please make sure it is an Advance function or 
        with Param blocks defined properly.

    .PARAMETER InputObject
        Run script against these specified objects. Takes input from Pipeline or when specified explicitly.

    .PARAMETER MaxThreads
        Number of threads to be executed in parallel, by default it creates one thread per CPU

    .PARAMETER RPS
        Use this switch if you want to run the command using Remote Powershell.
        By default, this script auto detects Exchange remote powershell, but can be passed as a parameter as well to support custom remoting.

    .PARAMETER Force
        By default this script does error checking for the first instance. If the first job fails, likely all jobs would, so just bail out. Using –Force parameter bypasses this check.
        Use this parameter if you know the parameters passed are correct and also useful when you are Scheduling the script and should not be prompted

    .PARAMETER WaitTimeOut
        When Force switch is not mentioned, the script waits for WaitTimeOut (by default, 30 seconds) for the first job to complete for Error checking.
	 If your jobs are long running and you know the Parameters used are correct, use –Force switch.
    
    .PARAMETER ModulestoLoad
        Powershell Module names that needs to be loaded in to the runspace that are required to execute the commands used in the External script (PS1). Comma separate the modules if there are more than one.
        This parameter is not required if you are using a command from any powershell Module

    .PARAMETER SnapinstoLoad
        Powershell Snapin names that needs to be loaded in to the runspace that are required to exectue the commands used in the External script (PS1).
        This parameter is not required if you are using a command from any powershell Module
      
    .PARAMETER BatchSize
        By default the function uses BatchSize of 100. This parameter is to limit the number of jobs that are to be Queued for running at a time and to process it in batches.
        For Example, If BatchSize is 20
        Queue 40 Jobs (BatchSize * 2)
        Wait until 20 jobs completes
        Queue the next batch of 20

    .PARAMETER PauseInMsec
        Delay to be induced between each batch. Before Queueing the subsequent batches, the script pauses for MilliSeconds mentioned.
        BatchSize and PauseInMsec can be used if Multithreading is overloading the Source or destination.
        It's very useful when running jobs against Exchange online, there are no magic numbers for this parameter, use wisely.

    .PARAMETER Quiet
        Do not display the progress bar. Can be used when scheduling the script.
        Using Quiet mode also speeds up the script as displaying progress bar is not required.

    .Example
        
        Get-Mailbox -database 'db1' | invoke-all {Get-MailboxFolderStatistics -Identity $_.name -Folder Scope "inbox" -IncludeOldestAndNewestItems }  | Where-Object{$_.ItemsInFolder -gt 0} | Select Identity, Itemsinfolder, Foldersize, NewestItemReceivedDate

        Actual command:
        Get-Mailbox -database 'db1' | Get-MailboxFolderStatistics -FolderScope "inbox" -IncludeOldestAndNewestItems | Where-Object{$_.ItemsInFolder -gt 0} | Select Identity, Itemsinfolder, Foldersize, NewestItemReceivedDate
        
    .Example
        
        Get-Mailbox -database 'db1' | invoke-all {Get-MailboxFolderStatistics -Identity $_.name -FolderScope "inbox" -IncludeOldestAndNewestItems } -Force | Where-Object{$_.ItemsInFolder -gt 0}
        
        Above command was ran from RPS (Exchange mangement Shell or Cloud PS session)
        Actual command:
        Get-Mailbox -database 'db1' | Get-MailboxFolderStatistics -FolderScope "inbox" -IncludeOldestAndNewestItems | Where-Object{$_.ItemsInFolder -gt 0}
       
        Note: When running from RPS, we need to specifiy all the parameters to the cmdlet for this function to work

    .Example
        
        Get-AzureRmVM -ResourceGroupName 'MyAzureRG' | Invoke-all { Start-AzureRmvm -ResourceGroupName $_.ResourceGroupname -Name $_.Name } -Force
        Command ran from Azure module imported PS console. This command Starts all VMs in Parallel.

        Actual Command:
        Get-AzureRmVM -ResourceGroupName 'MyAzureRG' | foreach { Start-AzureRmvm -Name $_.name -ResourceGroupName $_.ResourceGroupname }

    .Example

        Get-Mailbox -ResultSize 100 | Invoke-All {.\GetPWDsetUsrs.ps1 -Name $_.Alias} -ModulestoLoad Activedirectory
        Above command is an example on how to use the function with External scripts.

        ---------------------------------------GetPWDsetUsrs.ps1-----------------------------------------------
        param(
	    [String]$Name = ''
        )

            $90_Days = (Get-Date).adddays(-90)
            return Get-ADUser -filter {(mailnickname -eq $Name) -and (passwordlastset -le $90_days)} -properties PasswordExpired, PasswordLastSet, PasswordNeverExpires
        ---------------------------------------------------------------------------------------------------------

    .Example
        Get-ADComputer -Filter {name -like "*fs*"} | Invoke-All { C:\scripts\get-uptime.ps1 -ComputerName $_.DnsHostname}

    .Example
        $MBX | Invoke-All { Get-MobileDeviceStatistics -Mailbox $_.userprincipalname } -PauseInMsec 500 | `
        Select-Object @{Name="DisplayName";Expression={$input.Displayname}},Status,DeviceOS,DeviceModel,LastSuccessSync,FirstSyncTime | `
        Export-Csv c:\temp\devices.csv –Append

        Collects Mobile device statistics in batches of 100 at a time and Sleeps for 500 MilliSeconds between batches.
        This is very useful if you are using the script on a remote powershell and getting throttled, especially with Exchange online.
        

    #>

[cmdletbinding(SupportsShouldProcess = $True,DefaultParameterSetName='ScriptBlock')]
Param (   
        [Parameter(Mandatory=$True,position=0,ParameterSetName='ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ParameterSetName='ScriptBlock')]
        $InputObject,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [int]$MaxThreads = ((Get-CimInstance Win32_Processor) | Measure-Object -Sum -Property NumberOfLogicalProcessors).Sum,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [SWITCH]$RPS,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [SWITCH]$Force,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [INT]$WaitTimeOut = 30,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [ARRAY]$ModulestoLoad = @(),
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [ARRAY]$SnapinstoLoad = @(),
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [INT]$BatchSize = 100,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [INT]$PauseInMsec = 0,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false,ParameterSetName='ScriptBlock')]
        [SWITCH]$Quiet
)

#Discover the command that is being ran and prepare the Runspacepool objects
Begin{
	#Script uses Command Asts and lot other features that are available only on/after PS Version 3
    If($host.Version.Major -lt [INT]'3'){
        Write-Host "This Script requires Powershell version 3 or greater." -ForegroundColor Red
        Break
    }

	Set-StrictMode -Version Latest

#region begin init
	#Command User is running
    [String]$Global:Command = ''
	#Variable to hold custom function string that we create, this is to retrieve the parameters and Values passed to the command
	[String]$strfunc = $NULL
	#Proxycommand the script creates from the $Strfunc to validate and retrieve the parameters
    [String]$ProxyCommand = ''
	#Detect if the command supports value from Pipeline
    [BOOL]$SupportsValfromPipeLine = $false
    #Store the command details, like modules used etc
    $Commandinfo = $NULL
	#Find the command type that is being ran, it can be a cmdlet, function or a external script
    $Commandtype = New-Object System.Management.Automation.CommandTypes
    #Runspace pool for the jobs
	$runspacepool = $NULL
	#using Hashtable for performance, store all Jobs created to process later
    $Jobs = @{}
    [int]$i = 0
	#At first the JobCounter needs to be doubled to let some jobs be in running state when we are collecting the completed jobs
	[int]$JobCounter = $BatchSize * 2
    #Counter to keep track of Jobscollected so far
	[int]$script:jobsCollected = 0
	$Code = $NULL
    #Var to store the Metadata of the command being ran
	$MetaData = ''
	#For remote powershell we need to use the ConnectionInfo to create the session
    $Coninfo = New-Object System.Management.Automation.Runspaces.WSManConnectionInfo
	#Unique file name for each run
    [String]$Script:Logfilename = "InvokeAll_$(Get-Date -format "yyyyMMdd_HHmmss").log"
    $Script:Logfile = $NULL
	#Timer to keep track of time spent on each section
	$Timer = [system.diagnostics.stopwatch]::StartNew()
    #Record the JOB (this is not the error from the script) that had error streams in an array so it can be reported seperately.
    $Script:JobErrs = @()

#endregion init

#region begin Functions

    #logging function
    #Create a new log file for each run, if file is already present, append it.
    function Write-Log
    {
    [CmdletBinding()] 
        Param 
        (
            [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
            [ValidateNotNullOrEmpty()] 
            [String]$Message,

            [Parameter(Mandatory=$false)]
            [ValidateScript({ Test-Path "$_" })]
            [string]$LogPath= "$($PSScriptRoot)"
        
        )
		#If Logfile is not created yet, create one. This script uses the ScriptRoot directory by default
        if(-not $Script:Logfile){

            $LogPath = $LogPath.TrimEnd("\")
            if(Test-Path "$LogPath\$Script:Logfilename"){
                $Script:LogFile = "$LogPath\$Script:Logfilename"
        
            }Else{
                $Script:LogFile = New-Item -Name "$Script:Logfilename" -Path $LogPath -Force -ItemType File
                Write-Verbose "Created New log file $Script:LogFile"
            }
        }
    
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Verbose "[$FormattedDate] $Message"
        "[$FormattedDate] $Message" | Out-File -FilePath $LogFile -Append    
    }

    #CollectJobs:
    #Collect the Jobs that are completed. The function will return when the Jobs collected are greater or equal to the Batchsize
	#User may also choose to terminate the script by pressing Ctrl+C in between batches
    Function CollectJobs{
    Param([hashtable]$Jobs,[int]$BSize, [ref]$Jobscollected, [ref]$JobErrs)

        [int]$CurCollection = 0
        $JobsInProgress = @()
        

        do{
			#return if all jobs are completed
            if((@($Jobs.Values.Handle | Where-Object{$NULL -ne $_})).count -le 0){
                Write-Log "All Jobs are Completed"
                Return
            }    
            #If there are no completed jobs, wait for atleast one using Eventing Wait, simply looping to check if jobs are completed will consume resources
            if((@($Jobs.values | Where-Object{$NULL -ne $_.Handle -AND $_.Handle.Iscompleted -eq $true})).count -le 0){
                #If 80% of the Jobs in batch are completed, Go back and Invoke more jobs, this is avoid waiting on the batch if there are couple or few jobs that are long running
                if((($CurCollection / $BSize)*100) -gt 80){ 
                    Return 
                }
                If(-Not $Quiet) {
					Write-Progress -id 2 -Activity "Running Jobs" `
                    -Status "$JobNum / $TotalObjects Jobs Invoked. $(@($Jobs.Values.GetEnumerator() | Where-Object{($NULL -ne $_.Thread) -and $_.Thread.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Running}).Count) Jobs are in Running State..Waiting for atleast one to complete" `
                    -PercentComplete $(($JobNum / $TotalObjects)*100)
                }
                #WaitAny has 64 Handle limitation. limit the wait on first 60 handles
                $JobsInProgress = $Jobs.Values.GetEnumerator() | Where-Object{($NULL -ne $_.Thread) -and $_.Thread.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Running} | Select-Object -First 60
                $CompletedHandles = $Null
				#Waittime is in Milliseconds
                [int]$WaitTimeMS = $WaitTimeOut * 1000 
                #Waittime for the job to complete, if it didnt, loop back
                #If the User has pressed Ctrl+c inbetween the wait, the script will terminate and Outer finally block is executed
				#WaitAny retuns the Index of the completed Job
                if($JobsInProgress){
                    do{
						Write-Log "Waiting on the Handle for job completion"
                        $CompletedHandles = [System.Threading.WaitHandle]::WaitAny($JobsInProgress.Handle.AsyncWaitHandle,$WaitTimeMS)
                    }While($CompletedHandles -eq [System.Threading.WaitHandle]::WaitTimeout)
                }
            }            

   	        #Collect All jobs that are completed, it could be greater than the Batchsize, collect them anyway as they are completed
            ForEach ($Job in $($Jobs.Values.GetEnumerator() | Where-Object {($NULL -ne $_.Handle) -and $_.Handle.IsCompleted -eq $True})){
                try{
					#Collect the result of the completed Job and send it to the next pipeline or Host
					$Job.Thread.EndInvoke($Job.Handle)
					#Increment the Collection counters
					$CurCollection++;$Jobscollected.value++
					If(-not $Quiet){
						Write-Progress `
						-id 22  -ParentId 2 `
						-Activity "Collecting Jobs results that are completed... BatchSize: $BSize " `
						-PercentComplete ($Jobscollected.value / $Jobs.Count * 100) `
						-Status "$($Jobscollected.Value) / $($Jobs.Count)"
					}
                }Catch{
					Write-Error "Error on Thread EndInvoke : $_"
					Write-Log "Error on Thread EndInvoke : $_"
					Write-Host "It was processing Object $($Job.Object) . Job ID: $($Job.ID)" -ForegroundColor Yellow
					Write-Log "It was processing Object $($Job.Object) . Job ID: $($Job.ID)"
                }finally{
					if ($Job.Thread.HadErrors) {
						$Job.Thread.Streams.Error.ReadAll() | ForEach-Object {
                            #While outputing the job object on the screen and log 
                            $JobError = ''| Select JobObject, JobID, ErrorStr
                            $JobError.JobObject = $Job.Object
                            $jobError.JobID = $Job.ID
                            $JobError.ErrorStr = $_.Exception.Message.Tostring()
                            $JobErrs.Value += $JobError
							Write-Error "The pipeline had error $_ "
							Write-Host "It was processing Object $($Job.Object) . Job ID: $($Job.ID)" -ForegroundColor Yellow
							Write-Log "The pipeline had error $_ "
							Write-Log "It was processing Object $($Job.Object) . Job ID: $($Job.ID)"
							}
					}
					$Job.Thread.Dispose()
					$Job.Thread = $Null
					$Job.Handle = $Null
                }
            }
        }until($CurCollection -ge $BSize)
		#Collect until the BatchSize is reached, when done, go back and Invoke the next batch
    
    }

#endregion Functions

	Write-Log " Starting to Execute - Invoke-all 2.5 "
	Write-Log "$($myinvocation.Line)"

#region begin CommandDiscovery
#Find the command being used, we need this to create the Proxy command which is used to identify the parameters and its values used.
#The identified parameters and values are then used to construct the Runspaces for Parallel processing.

    #Collect the command details using ASTs. It could be a External Script, Cmdlet, Custom function
    try{
		$CommandAsts = $scriptblock.Ast.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]} , $true)
		$Elements = $CommandAsts.GetEnumerator().commandelements
		#First Element is the command we want to process
		$Element = $elements[0]

		Write-Log "Got command $($Element.Value) to process"
    
		switch($element.gettype().name){
			#Anything that has single quote and double Quote is also of this type
			StringConstantExpressionAst {
				#Commands are expressed as String, we are not intertested in Parameters or Variables
				if($element.StringConstantType -eq 'Bareword'){
					$CommandInfo = Get-Command $element.value -ErrorAction Stop -ErrorVariable Cmderr
					#Find the CommandType, All of the below types are supported
					$Commandtype = $CommandInfo.CommandType
					switch($Commandtype){
						Cmdlet         { $Global:Command = $element.Value}
						Function       { $Global:Command =  $element.Value}
						ExternalScript { $Global:Command = $element.Value}
            
					}
				}
				#else{throw "Not able to recoginize the command"}             
			}

		}
    }Catch{
        Write-Error "Error processing command: $Cmderr"
        Write-Log "Error processing command: $Cmderr"
        Write-Host "Unable to Process, Please check the command that is passed on the script block" -ForegroundColor Yellow
        break
    
    }

#endregion CommandDiscovery

#region begin CreateProxyCmd
#If we have found what command is being ran, create the Proxy command.
#Proxy command is used to find the Parameters that are used on the actual command.
#This way, we dont have to copy all the local variables and other stuff to the each Runspace.


    If($Global:Command){
		#Metadata of the command is used to create the Proxycommand.
        $MetaData = New-Object System.Management.Automation.CommandMetaData ($Commandinfo)
		#If no parameters are passed, there is no purpose for this script
        if($MetaData.Parameters.Count -le 0 -and (-not $Force)){
            Write-Error "$Global:Command doesnt use any parameters, the Input parameter from Pipeline cannot be bound correctly to this command"
            Write-Log "$Global:Command doesnt use any parameters, the Input parameter from Pipeline cannot be bound correctly to this command"
            Write-Host "If it is a custom script, make sure the Param blocks are defined correctly" -ForegroundColor Yellow
            Break
        
        }
		#Create the custom function, a.k.a ProxyFunction
		#Remove the body of the actual function and replace it with the custom code to return the Parameters used.
        $PScript = [System.Management.Automation.ProxyCommand]::Create($MetaData)
		$PScript = [scriptblock]::Create($PScript) 
		$Paramblock = $PScript.ast.ParamBlock.ToString()
		$strfunc = $strfunc + $Paramblock
        $strfunc += "`n `$ParamsPassed = `$PSBoundParameters `n"
        $strfunc += "return `$ParamsPassed"

		#The command Support values from Pipeline, User doesnt have explicity mention the parameter, handle it on the below block
        if(($strfunc.ToLower()).contains('valuefrompipeline')){ 
            $SupportsValfromPipeLine = $True
            Write-Log "This command supports ValueFromPipeline"
        }
        
		#For External Script, strip the file name to name the ProxyFunction
        if($Commandtype -eq 'ExternalScript'){
            $ProxyCommand = ($Global:Command.Split('\')[-1]).replace(".ps1","Proxy.ps1")
			#Also Copy the Script to pass it on to the Runspace
            $Code = [ScriptBlock]::Create($(Get-Content $MetaData.Name | Out-String))
        }else{
            $ProxyCommand = "$Global:Command" + "Proxy"
        }

		#Create the custom function, a.k.a ProxyFunction
        try{
			if(Get-Command -CommandType function | Where-Object{$_.name -eq "$ProxyCommand"}){
				#Remove if there is a duplicate, it is there from a previous failure
				Remove-Item function:\$ProxyCommand -Confirm:$false
			}
			New-Item -Path function:global:$ProxyCommand -Value $strfunc -ErrorAction Stop -ErrorVariable Cmderr | Out-Null
        
        }catch{
			Write-Error "Unable to create the Proxy command, Error : $cmderr"
			Write-Log "Unable to create the Proxy command, Error : $cmderr"
			Break
        }

        Write-Log "Created the Proxy command $ProxyCommand"
        

    }else{

        Write-Error "Sorry, This script is not capable of handling the command or alias you passed"
        Write-Log "Sorry, This script is not capable of handling the command or alias you passed"
        Break
    }
#endregion CreateProxyCmd

#region begin PrepRunspace
#Possiblites are RemotePowershell or Local. If it is local we will need to identify the module that is required to run the command and load it.

    #Find if the command is from (Exchange) Remote powershell
    if($Commandinfo.Module){ 
        #Detect RPS even though it is not mentioned explicity
		if(-not $RPS -and ((Get-Module $CommandInfo.Module).Description.Contains("Implicit remoting"))){ 
            Write-Log "Setting RPS to True"
            $RPS = $True
        }
    }
    #Create the sessionstate object based on the command discovery
	#Inspect the PS console from where the command was ran. For RPS, copy the Session Configuration. For Cmdlets from Modules, Import the modules.
    if($RPS){
		#Find the Remote session that is currently active. If for some reasons the session broke inbetween the script, user needs to fix it and re-run the script
        $RemoteSession = Get-PSSession | Where-Object{$_.state -eq 'opened' -and $_.configurationname -eq 'Microsoft.Exchange'} | Select-Object -First 1
        If(-not $RemoteSession){
            Write-Host "Unable to find the session configuration, please reconnect the session and try again" -ForegroundColor Red
            Write-Log "Unable to find the session configuration, please reconnect the session and try again"
            break
        }
        #if a valid RPS is found, copy the connectionInfo to use it on the runspaces
        $Coninfo = $RemoteSession.Runspace.ConnectionInfo.copy()
        
        #The Remote Powershell serialize and Deserialize the objects during transfer on the wire. Add the Typedata on best effort basics.
        #Type collection is required for the object to work correctly, we are most concered about the Serialazationdepth property
        #Create a typetable with the default types
        $TypeTable = [System.Management.Automation.Runspaces.TypeTable]::LoadDefaultTypeFiles()

        #Get all the TypeData using the below command and add it to the TypeTable.
        #If Exchange management Shell is not installed, Exchange datatypes are not loaded.
        $TypeDatas = Get-TypeData
        
        Foreach($typeData in $TypeDatas){
            try{
                $TypeTable.AddType($typeData)
            }Catch{
                #Ignore any errors adding TypeData, use it only for debugging purposes
                Write-Debug $_
            }
        }
        
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $Coninfo, $Host)
    }Else{
        #The command is from a module or Snapin, Prepare the SessionState object.
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        
        #Try and load if there are any custom object Types or just load the default ones
        $Types = Get-ChildItem "$($PSScriptRoot)\" -Filter *Types* | Select -ExpandProperty Fullname 
        $Types | ForEach { 
            $TypeEntry = New-Object System.Management.Automation.Runspaces.TypeConfigurationEntry -ArgumentList $_ 
            $sessionstate.Types.Append($TypeEntry) 
        }

        #Find module or PSsnapin to load to the session state
        if($Commandinfo.ModuleName){

            if((Get-Module $Commandinfo.ModuleName -ErrorAction SilentlyContinue)){
                [VOID]$sessionstate.ImportPSModule( $Commandinfo.ModuleName )
                Write-Log "Imported Module $($Commandinfo.ModuleName)"
            }else{
                if((Get-PSSnapin $Commandinfo.ModuleName -ErrorAction SilentlyContinue)){
                    [void]$Sessionstate.ImportPSSnapIn($Commandinfo.ModuleName,[ref]$null)
                    Write-Log "Imported PSSnapin $($Commandinfo.ModuleName)"
                }
            }

        }
        else{
			#If module is not found, its likely a local function or script, Load the modules that are specified by the user
			$Cmderr = $NULL
			foreach($Snapin in $SnapinstoLoad){
				try{
					Get-PSSnapin $Snapin -ErrorAction Stop -Registered -Verbose:$false | ForEach-Object{
					[void]$Sessionstate.ImportPSSnapIn($_.Name ,[ref]$null)
					Write-Log "Added Snapin $($_.name)"
					}
				}Catch{
					Write-Error "Unable to Load Snapin $Snapin"
					Write-Log "Unable to Load Snapin $Snapin"
				}
                
			}
			foreach($Module in $ModulestoLoad){
				try{
					Get-Module $Module -ListAvailable -All -ErrorAction Stop -Verbose:$false | ForEach-Object{
					[VOID]$sessionstate.ImportPSModule($_.Name)
					Write-Log "Added Module $($_.name)"
					}
				}Catch{
					Write-Error "Unable to Load Module $Module"
					Write-Log "Unable to Load Module $Module"
				}
			}

            #Check if it is a custom function from a local script and load the function to sessionstate
            if((Get-item Function:\$Global:Command -ErrorAction SilentlyContinue).ScriptBlock.File){

                Write-Log "The command $Global:Command is a custom function from file $((Get-item Function:\$Global:Command -ErrorAction SilentlyContinue).ScriptBlock.File)"
                $Definition = Get-Content Function:\$Global:Command
                $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Global:Command, $Definition
                [VOID]$sessionstate.Commands.Add($SessionStateFunction)

            }elseif($Commandtype -eq 'ExternalScript'){
                Write-Log "The command passed is an External Script"
            }else{
                Write-Log "Unable to find the Module or snap-in to load"
            }
        }
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionstate, $Host)
    }
    $runspacepool.Open() 
    
#endregion PrepRunspace
	#Trace time took on Process and End Blocks
    $Timer.Start() 

} #End Begin

Process{ 
	#This Block runs for each object
	#For each object discover the Parameters, values and add it to the Job Object
	#int Locals
    $error.clear()    
    #$tempscriptblock and $SscriptblockBkp is used to the store the modified command
	$tempScriptBlock = ''
    $paramused = $NULL
    $i++

#region begin ParamDiscovery
    #Modify the command from the user command with the Proxycommand, we will then pass the Inputobject from Pipeline to fetch the parameters used on the command
    $tempScriptBlock = ($ScriptBlock.ToString()).Replace($Global:Command,$ProxyCommand)
    $tempScriptBlock = $tempScriptBlock.Replace('$_', '$inputobject')
    #take a backup, some commands doesnt bind properly with the Pipeline object
	$ScriptBlockBKP = $tempScriptBlock
	#Use the inputobject from the Pipeline if the command supports it
    if($SupportsValfromPipeLine){
        $tempScriptBlock = "`$inputobject | " + $tempScriptBlock
    }
    $tempscriptblock = [Scriptblock]::Create($tempScriptBlock)

    #try using the Pipelineobject and if it fails try without it
    try{
		$paramused = Invoke-Command -ScriptBlock $tempScriptBlock -ErrorAction SilentlyContinue -ErrorVariable Cmderr
    
		if ($Cmderr -and $Cmderr[-1].Exception.ErrorId -eq 'InputObjectNotBound'){

			Write-Host "Encountered error, but it's ok, retrying without the Pipeline Inputobject" -ForegroundColor Yellow
			Write-Log "Encountered error, but it's ok, retrying without the Pipeline Inputobject"

			#Retry without the Pipeline object
			$tempScriptBlock = [Scriptblock]::Create($ScriptBlockBKP)
			$paramused = Invoke-Command -ScriptBlock $tempScriptBlock -ErrorAction SilentlyContinue -ErrorVariable Cmderr

			If($Cmderr){

				Write-Error "Unable to execute the proxy command $($ProxyCommand) . Please verify if mandatory parameters are mentioned, if Command accepts ValueFromPipeline, do not explicity mention it as a Parameter."
				Write-Log "Unable to execute the proxy command $($ProxyCommand)"
				throw $Cmderr
			}

			$SupportsValfromPipeLine = $false
		}
 
#endregion ParamDiscovery

#region begin ErrChk    
		$Handle = $NULL
		#Check if we are able to execute the command for the first object. If it fails, likely all threads would, so quit right there
		if($i -eq 1 -and (-not $Force)){
			#Create the powershell instance, load the command, parameter and values, $Powershell is the thread that doesnt the actual work
			$Powershell = [powershell]::Create()
			#for a script, add it as a script
			if($Commandtype -eq 'ExternalScript'){
				[VOID]$Powershell.AddScript($Code)
			}else{
				[VOID]$Powershell.AddCommand($Global:Command)
			}
			#Loop thru all the paramaters and its value, add it to the powershell instance just created
			foreach($item in $paramused.GetEnumerator()){
				$Powershell.AddParameter($item.Key,$item.value) | Out-Null
			}
			#Use the Runspace pool, so we can limit the Maxthreads that can run at a time.
			$Powershell.RunspacePool = $RunspacePool
			
			#PS Instance is ready, before preparing the other jobs, Error check the first instance
			$Handle = $Powershell.BeginInvoke()
			if($Powershell.InvocationStateInfo.State -ne [System.Management.Automation.PSInvocationState]::Completed){
				Write-Log "Running error check on the first instance"
				#Register for state change events on the First Job
				Register-ObjectEvent -InputObject $Powershell -EventName InvocationStateChanged -SourceIdentifier PSInvocationStateChanged

				Write-Log "Waiting for the Invocation state change, waits for $WaitTimeOut Seconds"
				Write-Log "Current State : $($Powershell.InvocationStateInfo.State)"
				#Wait for the first instance to complete, it waits for 30 seconds by default and is configurable
				if($Powershell.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Running){
					Wait-Event -SourceIdentifier PSInvocationStateChanged -Timeout $WaitTimeOut | Out-Null
				}
				#Still running?
				if($Powershell.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Running){
					#Prompt user if we need to abort or continue waiting
					if($PSCmdlet.Shouldcontinue(
						"Do you want to ABORT the operation ? If you dont like to wait for the first instance, Select YES and re-run using -Force Switch.
						Selecting NO will continue to wait Indefinitely for the first instance to Complete before Multi-Threading rest of the instances",
						"Timed-Out executing the first Instance of the command $Global:Command")
					){
						#If yes, Cleanup and Quit
						Throw "Aborting the operation"                
					}

					Write-Log "Waiting for the first instance to complete, forever"
					#wait forever for the first instance to complete
					Wait-Event -SourceIdentifier PSInvocationStateChanged | Out-Null

				}

				Write-Log "Done waiting on the first Instance"
			}
			#If First instance failed, error and quit
			if($Powershell.InvocationStateInfo.State -eq [System.Management.Automation.PSInvocationState]::Failed){

				Write-Error "Error invoking powershell thread. Reason: $($Powershell.InvocationStateInfo.Reason)"
				Write-Log "Error invoking powershell thread. Reason: $($Powershell.InvocationStateInfo.Reason)"
				Throw "Error from the powershell first Instance"
			}
		}
#endregion ErrChk
		#Create job object for each instance and add it to the Jobs array
		#$Handle is the AsyncEvent we wait or check on for job completion
		$Job = "" | Select-Object ID, Handle, Thread, Object, ParamsDict
		$Job.ID = $i
		#The first job is already invoked in the Process block if $force is not used, so just assign it here
		if($i -eq 1 -and (-not $Force)){ 
			$Job.Handle = $Handle
			$job.Thread = $Powershell
		}
		#parameters discovered using the Proxy command, add it to the Job
		$Job.ParamsDict = $paramused
		#Input object can be of any type, see if we cnovert to string and display for reporting purposes. There is no wild guess we can make here
		$Job.Object = $Inputobject.ToString()
		#Add each job to the job array to invoke later
		$Jobs.Add($Job.ID,$Job)

		If(-not $Quiet){
			Write-Progress -id 1 -Activity "Creating Job Object" -Status "Created $i Objects"
		}

    }catch{
        Write-Error "Caught Error : $_"
        Write-Log "Caught Error : $_"
        Write-Host "Please verify if mandatory parameters are mentioned, if Command accepts ValueFromPipeline, do not explicity mention it as a Parameter." -ForegroundColor Yellow
        Write-Log "Cleaning up; Error in Process block"
        if($Powershell){
            $Powershell.dispose()
        }
        $runspacepool.Close()
        $runspacepool.dispose()

        if(Get-Command -CommandType function | Where-Object{$_.name -eq "$ProxyCommand"}){
            Remove-Item function:\$ProxyCommand -Confirm:$false    
            Write-Log "Deleted the Proxy function $ProxyCommand"
        }
        if(Get-Event | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'}){ 
            Get-Event | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'} | Remove-Event
        }
        if(Get-EventSubscriber | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'}){
            Get-EventSubscriber | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'} | Unregister-Event
        }
        
        Write-Log "Disposed the Powershell runspace pool objects"
        Break
		
    }

}#End Process Block

#Invoke and collect the jobs as per the BatchSize, add pause if mentioned
End{
	#Cleanup the previous progress bars
    If(-Not $Quiet){
		Write-Progress -id 1 -Activity "Creating Job Object" -Completed
    }
    $Timer.Stop()
	#Total Jobs that are queued to be processed, they are invoked and collected per the batch size
    $TotalObjects = $Jobs.Count
    
    Write-Log "Time took to create the Jobs : $($Timer.Elapsed.ToString())"
    Write-Log "Total Jobs created $TotalObjects"
    
    #If there are no jobs to process, break out of the End Block
    if($TotalObjects -le 0){
        Write-Log "There are no Jobs to process, Exiting"
        Break
    }

    $Timer.Reset()
	#init the job counter var
    [INT]$JobNum = 0
    $Timer.Start()
	#SubTimer used to calculate time for batches
    $SubTimer = [system.diagnostics.stopwatch]::StartNew()

#region begin ProcessJobs
#Start to invoke the jobs, first invoke Batchsize * 2 Jobs and then collect Batchsize jobs. This way we always Queue one batch in running state while collecting the completed jobs.    
	try{
		#Create the Job instance for rest of the instances
		for($JobNum = 1 ; $JobNum -le $TotalObjects ; $JobNum++){ 
			$Job = $Jobs.Item($JobNum)
			#Skip the first job as it already invoked if Force switch is not specified
			if($Job.ID -eq 1 -and (-not $Force)){ Continue}
			#Below creating of job is same as the first instance process
			$Powershell = [powershell]::Create()
			
			if($Commandtype -eq 'ExternalScript'){
				[VOID]$Powershell.AddScript($Code)
			}else{
				[VOID]$Powershell.AddCommand($Global:Command)
			}
			#Add the parameters and values
			foreach($item in $Job.ParamsDict.GetEnumerator()){
				$Powershell.AddParameter($item.Key,$item.value) | Out-Null
			}

			$Powershell.RunspacePool = $RunspacePool
			$Job.Thread = $Powershell
			#Invoke the job when created
			$Job.Handle = $Job.Thread.BeginInvoke()
        
			If(-Not $Quiet){
				Write-Progress -id 2 -Activity "Running Jobs" `
					-Status "$JobNum / $TotalObjects Jobs Invoked." `
					-PercentComplete $(($JobNum / $TotalObjects)*100)

			}
			#Batch size is reached, lets start collecting the completed jobs before creating and invoking other Jobs
			if($JobNum -ge $JobCounter){
				#Timer for reports, reset it and use it for collecting jobs as well!
				$SubTimer.Stop()
				Write-Log "Time spent on Invoking Batch NO: $($Jobnum / $BatchSize) - $($SubTimer.Elapsed.ToString())"
				$SubTimer.Reset();$SubTimer.Start()

				CollectJobs $Jobs $BatchSize ([REF]$Script:jobsCollected) ([REF]$Script:JobErrs)
				Write-Log "Jobs Collected so far: $script:jobsCollected"

				$SubTimer.Stop()
				Write-Log "Time spent on Collecting Batch NO: $($Jobnum / $BatchSize) - $($SubTimer.Elapsed.ToString())"
				$SubTimer.Reset()
				#If Pause is specified, wait for the timeout specified
				if($PauseInMsec){
					Write-Log "Sleeping for $PauseInMsec Msecs"
					Start-Sleep -Milliseconds $PauseInMsec
				}

				$SubTimer.Start()
				$JobCounter += $BatchSize
				Write-Log "JobCounter : $JobCounter"
			}
    
		}
		#For loops increments the num by 1 on exit, so reset it back
		#All jobs are invoked at this time, just collect all of them using a bigger batchsize number
		$JobNum = $JobNum - 1
		Write-Log "Invoked all Jobs, Collecting the last jobs that are running"

		While ((@($Jobs.Values.Handle | Where-Object {$Null -ne $_})).count -gt 0){
			#We want to collect all the Jobs, so just double the BatchSize
			$BatchSize = (@($Jobs.Values.Handle | Where-Object {$Null -ne $_})).count * 2
			Write-Log "Using BatchSize: $BatchSize"
			CollectJobs $Jobs $BatchSize ([ref]$Script:jobsCollected) ([REF]$Script:JobErrs)
		}

		$Timer.Stop()
		Write-Log "Time took to Invoke and Complete the Jobs : $($Timer.Elapsed.ToString())"
		Write-Log "Jobs Collected: $script:jobsCollected"
    
		$Timer.Reset()

#endregion ProcessJobs
	}Catch{
		Write-Error "Error executing jobs : $_ "
	}Finally{
		#Cleanup
		If(-Not $Quiet){
		Write-Progress -id 22  -ParentId 2 -Activity "Collecting Jobs results that are completed, $BatchSize at a time" -Completed
		Write-Progress -id 2 -Activity "Running Jobs" -Completed
		}
		if($(($Jobs.Values.GetEnumerator() | Where-Object{$NULL -ne $_.Handle} | Measure-Object ).count) -gt 0){
        
			Write-Host "Terminating the $(($Jobs.Values.Handle | Where-Object{$Null -ne $_} | Measure-Object ).count) Job(s) that are still running." -ForegroundColor Red
			Write-Log "Terminating the $(($Jobs.Values.Handle | Where-Object{$Null -ne $_} | Measure-Object ).count) Job(s) that are still running."
			Foreach($Job in ($Jobs.Values.GetEnumerator() | Where-Object{$NULL -ne $_.Handle})){
				$Job.Thread.stop()
				$Job.Thread.Dispose()
				$Job.Thread = $Null
				$Job.Handle = $Null
			}
		}

		If($Timer.Isrunning){
			Write-Log "Exiting script"
			$Timer.Stop()
			Write-Log "Jobs Collected: $script:jobsCollected"
			Write-Log "Time took to Invoke and Complete the Jobs : $($Timer.Elapsed.ToString())"
		}
        if($Script:JobErrs.Count -gt 0){
            Write-Log "Errors from the Jobs"
            Write-Log "---------------------------------------------------------------------------------------------"
            foreach($JobError in $Script:JobErrs){
                Write-Log "$($JobError.JobObject) - $($JobError.ErrorStr)"
            }
            Write-Log "---------------------------------------------------------------------------------------------"
            $JobErrs = $NULL
        }
		if($Powershell){
			$Powershell.dispose()
		}
		$runspacepool.Close()
		$runspacepool.dispose()
		$Jobs.Clear()
		$Jobs = $NULL
		if(Get-Command -CommandType function | Where-Object{$_.name -eq "$ProxyCommand"}){
			Remove-Item function:\$ProxyCommand -Confirm:$false    
			Write-Log "Deleted the Proxy function $ProxyCommand"
		}
		if(Get-Event | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'}){ 
			Get-Event | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'} | Remove-Event
		}
		if(Get-EventSubscriber | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'}){
			Get-EventSubscriber | Where-Object{$_.SourceIdentifier -eq 'PSInvocationStateChanged'} | Unregister-Event
		}
		[gc]::Collect()
		Write-Log "Triggered GC, Script execution has completed"
	}
} #End End Block

}#End Function
