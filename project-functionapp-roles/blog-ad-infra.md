# The Story Behind Our Active Directory Infrastructure: From Bicep to PowerShell

## Introduction

Let’s rewind to the beginning. We needed a way to securely reset passwords in our on-premises Active Directory, but before any API could do its magic, we had to build the actual AD environment in Azure—robust, automated, and ready for anything. This is the story of how we did it, and why every piece fits together the way it does.

## The Blueprint: Bicep as Our Architect

We started with Bicep, Azure’s declarative language for infrastructure. Instead of clicking through endless Azure Portal screens, we wrote a template that describes everything:

- The domain controller VM, with spot pricing for cost savings (because why pay more for test/dev?)
- A dedicated VNet, subnets, and NSGs to keep traffic locked down
- Key Vault for secrets, Log Analytics for diagnostics, and all the glue that ties it together

Every parameter—domain name, NetBIOS name, admin credentials—can be set at deploy time. If you want to change the environment from dev to prod, it’s just a flag. The Bicep file is our single source of truth, and it’s versioned right alongside our code.

## Orchestration: Deploy-Complete.ps1, the Maestro

Once the infrastructure is described, we need to bring it to life. That’s where `Deploy-Complete.ps1` comes in. This PowerShell script isn’t just a wrapper—it’s the conductor of our deployment symphony.

First, it checks prerequisites. Are you logged into Azure? Is the Bicep CLI installed? Are all the parameter files in place? If not, it tells you what’s missing, so you’re never left guessing.

Then, it creates the resource group if it doesn’t exist, and kicks off the Bicep deployment. But here’s where things get interesting: if you’ve asked for a domain controller, the script doesn’t just create a VM and walk away. It waits for the VM to boot, then uses Azure’s Run Command to execute a custom PowerShell script inside the VM—no manual RDP, no fiddling with extensions.

## The Heartbeat: Domain Controller Promotion

Promoting a Windows Server to a domain controller is a delicate dance. The script inside the VM (`Bootstrap-ADDSDomain.ps1`) formats the data disk, installs the AD DS role, and then launches the actual promotion as a detached process. Why detached? Because the VM reboots during promotion, and we don’t want our orchestration to get stuck waiting for a process that’s about to disappear.

We log every step to `C:\temp`, so if anything goes wrong, you can see exactly where. The promotion script is generated on the fly, with all the right parameters—domain name, NetBIOS name, and a Safe Mode password that’s securely passed as Base64 and decoded in-guest. No more weird whitespace or complexity errors.

## Detecting the Reboot: Smarter Than PowerState

After the promotion, the VM reboots. But how do we know when it’s back and ready? Instead of relying on flaky PowerState checks, we query the VM’s boot time using CIM, and watch for it to change. If Run Command fails during reboot, we treat that as a sign the VM is in the reboot window. Once the boot time updates and AD Web Services are available, we know it’s safe to proceed.

## Post-Configuration: Making AD Useful

With the domain up, we run another script (`Configure-ADPostPromotion.ps1`) via Run Command. This one creates an Organizational Unit for our function app resources, sets up the service account (with just enough permissions to reset passwords), and creates a few test users for validation. It even updates the service account’s password if the account already exists—no manual cleanup needed.

All the logs go to `C:\temp`, and every step is wrapped in error handling. If something fails, you get a clear message, not a cryptic stack trace.

## Lessons Learned (and a Few Battle Scars)

We didn’t get it right the first time. There were plenty of hiccups:

- Passing SecureStrings between scripts and Bicep was trickier than expected. We ended up converting to plain text and Base64, then back to SecureString inside the VM.
- Scheduled tasks for promotion were unreliable—detached PowerShell processes worked much better.
- Detecting reboots by PowerState was hit-or-miss; boot time checks are far more reliable.
- Logging everywhere (especially to disk) made troubleshooting so much easier.

## The End Result: Automated, Auditable, and Secure

Now, spinning up a new AD environment is as simple as running a script. Every step is automated, every credential is handled securely, and every log is there if you need it. The infrastructure is ready for our password reset API, and we can redeploy, tear down, or troubleshoot with confidence.

If you’re building hybrid cloud solutions, don’t underestimate the value of good orchestration and clear logging. It’s the difference between a fragile demo and a production-ready system.

---

**Built with**: Bicep • PowerShell 7.4 & 5.1 • Azure Run Command • Key Vault • Log Analytics

**Ready for**: Real-world hybrid deployments, not just lab experiments.
