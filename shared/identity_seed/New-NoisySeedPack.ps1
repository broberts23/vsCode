Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$outputRoot = Join-Path $PSScriptRoot 'datasets\noisy'
if (-not (Test-Path $outputRoot)) {
    New-Item -ItemType Directory -Path $outputRoot | Out-Null
}

$seedVersion = '2026-04-v2-noisy'
$timestamp = '2026-04-27T18:00:00Z'

$departments = @(
    'Identity Operations',
    'Governance',
    'Finance',
    'Human Resources',
    'Security Operations',
    'Engineering',
    'Sales',
    'Customer Success'
)

$jobTitles = @(
    'Identity Administrator',
    'Security Analyst',
    'Governance Analyst',
    'Finance Analyst',
    'Project Manager',
    'Support Engineer',
    'Cloud Engineer',
    'HR Specialist'
)

$memberUsers = for ($index = 1; $index -le 54; $index++) {
    $department = $departments[($index - 1) % $departments.Count]
    $jobTitle = $jobTitles[($index - 1) % $jobTitles.Count]
    $risk = switch ($index % 10) {
        0 { 'high' }
        1 { 'medium' }
        2 { 'medium' }
        default { 'low' }
    }
    [ordered]@{
        id = ('user-member-{0:d3}' -f $index)
        user_principal_name = ('member{0:d3}@contosolab.onmicrosoft.com' -f $index)
        display_name = ('Member User {0:d3}' -f $index)
        user_type = 'Member'
        department = $department
        job_title = $jobTitle
        manager_id = if ($index -le 6) { 'user-member-001' } else { ('user-member-{0:d3}' -f ([Math]::Max(1, ($index % 6) + 1))) }
        group_ids = @()
        risk_state = $risk
        source = 'seed'
        seed_version = $seedVersion
        last_updated_utc = $timestamp
    }
}

$guestUsers = for ($index = 1; $index -le 12; $index++) {
    [ordered]@{
        id = ('user-guest-{0:d3}' -f $index)
        user_principal_name = ('guest{0:d3}_external#EXT#@contosolab.onmicrosoft.com' -f $index)
        display_name = ('Guest User {0:d3}' -f $index)
        user_type = 'Guest'
        department = 'Partner'
        job_title = 'External Consultant'
        manager_id = 'user-member-002'
        group_ids = @('group-b2b-collab')
        risk_state = if ($index % 4 -eq 0) { 'high' } else { 'medium' }
        source = 'seed'
        seed_version = $seedVersion
        last_updated_utc = $timestamp
    }
}

$users = @($memberUsers + $guestUsers)

$groups = @(
    [ordered]@{ id='group-pim-admins'; display_name='PIM Administrators'; group_type='Security'; classification='Privileged'; owner_ids=@('user-member-001'); member_ids=@('user-member-002','user-member-005','user-guest-004'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-access-reviewers'; display_name='Access Reviewers'; group_type='Security'; classification='Internal'; owner_ids=@('user-member-001'); member_ids=@('user-member-001','user-member-002','user-member-003','user-member-004'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-b2b-collab'; display_name='B2B Collaboration Guests'; group_type='Microsoft365'; classification='External'; owner_ids=@('user-member-003'); member_ids=@(($guestUsers | ForEach-Object { $_.id })); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-finance-app-users'; display_name='Finance App Users'; group_type='Security'; classification='Business'; owner_ids=@('user-member-010'); member_ids=@('user-member-011','user-member-012','user-member-013','user-member-014'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-finance-approvers'; display_name='Finance Approvers'; group_type='Security'; classification='Business'; owner_ids=@('user-member-010'); member_ids=@('user-member-010','user-member-015'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-security-ops'; display_name='Security Operations'; group_type='Security'; classification='Sensitive'; owner_ids=@('user-member-020'); member_ids=@('user-member-020','user-member-021','user-member-022','user-member-023'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-helpdesk-tier2'; display_name='Helpdesk Tier 2'; group_type='Security'; classification='Internal'; owner_ids=@('user-member-024'); member_ids=@('user-member-024','user-member-025','user-member-026'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-sales-crm-users'; display_name='Sales CRM Users'; group_type='Security'; classification='Business'; owner_ids=@('user-member-030'); member_ids=@('user-member-030','user-member-031','user-member-032','user-member-033','user-member-034'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-engineering-prod-readers'; display_name='Engineering Production Readers'; group_type='Security'; classification='Sensitive'; owner_ids=@('user-member-040'); member_ids=@('user-member-040','user-member-041','user-member-042','user-member-043'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-engineering-prod-contributors'; display_name='Engineering Production Contributors'; group_type='Security'; classification='HighlySensitive'; owner_ids=@('user-member-040'); member_ids=@('user-member-044','user-member-045'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-hr-confidential'; display_name='HR Confidential'; group_type='Security'; classification='Sensitive'; owner_ids=@('user-member-050'); member_ids=@('user-member-050','user-member-051'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='group-contractors'; display_name='Contractors'; group_type='Security'; classification='External'; owner_ids=@('user-member-002'); member_ids=@('user-guest-001','user-guest-002','user-guest-003','user-guest-004','user-guest-005'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

$groupMembership = @{}
foreach ($group in $groups) {
    foreach ($memberId in $group.member_ids) {
        if (-not $groupMembership.ContainsKey($memberId)) {
            $groupMembership[$memberId] = [System.Collections.Generic.List[string]]::new()
        }
        $groupMembership[$memberId].Add($group.id)
    }
}

foreach ($user in $users) {
    $user.group_ids = @($groupMembership[$user.id])
    if (-not $user.group_ids) {
        $user.group_ids = @()
    }
}

$roles = @(
    [ordered]@{ id='role-global-admin-001'; role_definition='Global Administrator'; principal_id='user-member-002'; assignment_type='Eligible'; scope='/'; start_utc='2026-04-01T00:00:00Z'; end_utc='2026-07-01T00:00:00Z'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-priv-role-admin-001'; role_definition='Privileged Role Administrator'; principal_id='user-member-001'; assignment_type='Active'; scope='/'; start_utc='2025-12-01T00:00:00Z'; end_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-groups-admin-001'; role_definition='Groups Administrator'; principal_id='user-guest-004'; assignment_type='Active'; scope='/'; start_utc='2026-04-10T00:00:00Z'; end_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-user-admin-001'; role_definition='User Administrator'; principal_id='user-member-024'; assignment_type='Active'; scope='/'; start_utc='2026-02-12T00:00:00Z'; end_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-security-reader-001'; role_definition='Security Reader'; principal_id='user-member-020'; assignment_type='Active'; scope='/'; start_utc='2026-01-15T00:00:00Z'; end_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-sharepoint-admin-001'; role_definition='SharePoint Administrator'; principal_id='user-member-030'; assignment_type='Eligible'; scope='/'; start_utc='2026-03-01T00:00:00Z'; end_utc='2026-09-01T00:00:00Z'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-billing-admin-001'; role_definition='Billing Administrator'; principal_id='user-member-010'; assignment_type='Active'; scope='/'; start_utc='2025-11-01T00:00:00Z'; end_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='role-exchange-admin-001'; role_definition='Exchange Administrator'; principal_id='user-member-003'; assignment_type='Eligible'; scope='/'; start_utc='2026-04-04T00:00:00Z'; end_utc='2026-08-30T00:00:00Z'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

$accessReviews = @(
    [ordered]@{ id='review-guest-access-q2'; name='Guest Access Q2 Review'; target_group_id='group-b2b-collab'; reviewer_ids=@('user-member-003'); reviewed_principal_ids=@(($guestUsers | ForEach-Object { $_.id })); status='inProgress'; due_utc='2026-05-05T23:59:59Z'; decisions=@(@{ principal_id='user-guest-004'; decision='NotReviewed' }, @{ principal_id='user-guest-008'; decision='Deny' }); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='review-privileged-membership-apr'; name='Privileged Membership April Review'; target_group_id='group-pim-admins'; reviewer_ids=@('user-member-001'); reviewed_principal_ids=@('user-member-002','user-member-005','user-guest-004'); status='overdue'; due_utc='2026-04-20T23:59:59Z'; decisions=@(@{ principal_id='user-member-002'; decision='Approve' }, @{ principal_id='user-guest-004'; decision='NotReviewed' }); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='review-finance-access-may'; name='Finance Access May Review'; target_group_id='group-finance-app-users'; reviewer_ids=@('user-member-010'); reviewed_principal_ids=@('user-member-011','user-member-012','user-member-013','user-member-014'); status='inProgress'; due_utc='2026-05-09T23:59:59Z'; decisions=@(@{ principal_id='user-member-014'; decision='Approve' }); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='review-prod-contrib-q2'; name='Production Contributor Q2 Review'; target_group_id='group-engineering-prod-contributors'; reviewer_ids=@('user-member-040'); reviewed_principal_ids=@('user-member-044','user-member-045'); status='inProgress'; due_utc='2026-05-12T23:59:59Z'; decisions=@(); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

$evidence = @(
    [ordered]@{ id='evidence-signin-001'; evidence_type='signinLog'; title='Suspicious sign-in with impossible travel'; principal_id='user-member-002'; uri='seed://noisy/signin-001.json'; summary='Two sign-ins occurred within 11 minutes from London and Singapore.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='evidence-note-001'; evidence_type='analystNote'; title='Analyst note on PIM activation timing'; principal_id='user-member-002'; uri='seed://noisy/note-001.md'; summary='PIM elevation occurred four minutes after the suspicious sign-in.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='evidence-group-001'; evidence_type='groupSnapshot'; title='Privileged group membership snapshot'; principal_id='user-guest-004'; uri='seed://noisy/group-001.json'; summary='Guest user remains a member of PIM Administrators.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='evidence-policy-001'; evidence_type='policyExcerpt'; title='External users in privileged groups policy'; principal_id=$null; uri='seed://noisy/policy-001.md'; summary='Guests must not retain standing membership in privileged groups.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='evidence-hr-001'; evidence_type='hrEvent'; title='HR leaver event'; principal_id='user-member-013'; uri='seed://noisy/hr-001.json'; summary='HR marked Member User 013 as terminated but access still exists.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='evidence-group-002'; evidence_type='groupSnapshot'; title='Finance access group snapshot'; principal_id='user-member-013'; uri='seed://noisy/group-002.json'; summary='Terminated user remains in Finance App Users.'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

for ($index = 1; $index -le 18; $index++) {
    $userId = ('user-member-{0:d3}' -f ((($index + 14) % 54) + 1))
    $evidence += [ordered]@{
        id = ('evidence-signin-{0:d3}' -f ($index + 10))
        evidence_type = 'signinLog'
        title = ('Suspicious sign-in pattern {0:d3}' -f $index)
        principal_id = $userId
        uri = ('seed://noisy/signin-{0:d3}.json' -f ($index + 10))
        summary = ('Noisy telemetry event {0:d3} for {1}.' -f $index, $userId)
        source = 'seed'
        seed_version = $seedVersion
        last_updated_utc = $timestamp
    }
}

$incidents = @(
    [ordered]@{ id='incident-impossible-travel-001'; title='Impossible travel followed by privileged role activation'; severity='high'; status='active'; principal_id='user-member-002'; occurred_utc='2026-04-26T08:14:00Z'; signals=@('impossibleTravel','pimActivation','newCountry'); evidence_ids=@('evidence-signin-001','evidence-note-001'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='incident-guest-privilege-001'; title='Guest account discovered in privileged admin group'; severity='high'; status='investigating'; principal_id='user-guest-004'; occurred_utc='2026-04-25T16:32:00Z'; signals=@('guestPrivilegedMembership','accessReviewOverdue'); evidence_ids=@('evidence-group-001','evidence-policy-001'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='incident-terminated-user-001'; title='Terminated user still enabled in finance application group'; severity='medium'; status='active'; principal_id='user-member-013'; occurred_utc='2026-04-26T09:05:00Z'; signals=@('hrTermination','staleAccess'); evidence_ids=@('evidence-hr-001','evidence-group-002'); source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

for ($index = 1; $index -le 15; $index++) {
    $userId = ('user-member-{0:d3}' -f ((($index + 8) % 54) + 1))
    $severity = if ($index % 5 -eq 0) { 'high' } elseif ($index % 2 -eq 0) { 'medium' } else { 'low' }
    $incidents += [ordered]@{
        id = ('incident-noisy-{0:d3}' -f $index)
        title = ('Noisy incident scenario {0:d3}' -f $index)
        severity = $severity
        status = if ($index % 3 -eq 0) { 'investigating' } else { 'active' }
        principal_id = $userId
        occurred_utc = ('2026-04-{0:d2}T{1:d2}:12:00Z' -f ((($index % 9) + 18)), ((($index * 2) % 10) + 8))
        signals = @('anomalousSignIn', 'conditionalAccessChallenge')
        evidence_ids = @(('evidence-signin-{0:d3}' -f ($index + 10)))
        source = 'seed'
        seed_version = $seedVersion
        last_updated_utc = $timestamp
    }
}

$approvals = @(
    [ordered]@{ id='approval-disable-user-001'; request_type='DisableUser'; target_principal_id='user-member-013'; requested_by_id='user-member-002'; approver_ids=@('user-member-001'); status='approved'; justification='Confirmed termination from HR event.'; requested_utc='2026-04-26T09:00:00Z'; resolved_utc='2026-04-26T09:15:00Z'; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp },
    [ordered]@{ id='approval-remove-guest-001'; request_type='RemoveGroupMember'; target_principal_id='user-guest-004'; target_group_id='group-pim-admins'; requested_by_id='user-member-003'; approver_ids=@('user-member-001'); status='pending'; justification='Guest account is still present in a privileged group after overdue review.'; requested_utc='2026-04-27T08:30:00Z'; resolved_utc=$null; source='seed'; seed_version=$seedVersion; last_updated_utc=$timestamp }
)

for ($index = 1; $index -le 10; $index++) {
    $userId = ('user-member-{0:d3}' -f ((($index + 20) % 54) + 1))
    $approvals += [ordered]@{
        id = ('approval-noisy-{0:d3}' -f $index)
        request_type = if ($index % 2 -eq 0) { 'RemoveGroupMember' } else { 'DisableUser' }
        target_principal_id = $userId
        target_group_id = if ($index % 2 -eq 0) { 'group-contractors' } else { $null }
        requested_by_id = 'user-member-002'
        approver_ids = @('user-member-001')
        status = if ($index % 3 -eq 0) { 'pending' } else { 'approved' }
        justification = ('Noisy approval workflow {0:d3} generated for testing.' -f $index)
        requested_utc = ('2026-04-{0:d2}T10:00:00Z' -f ((($index % 9) + 18)))
        resolved_utc = if ($index % 3 -eq 0) { $null } else { ('2026-04-{0:d2}T10:25:00Z' -f ((($index % 9) + 18))) }
        source = 'seed'
        seed_version = $seedVersion
        last_updated_utc = $timestamp
    }
}

$eval = @(
    [ordered]@{ id='eval-noisy-governance-001'; lab='core-1'; prompt='Which guest accounts remain in privileged or overdue review scenarios?'; expected_fact_ids=@('user-guest-004','review-privileged-membership-apr') },
    [ordered]@{ id='eval-noisy-ops-001'; lab='core-2'; prompt='Which approval requests are still pending for risky identity changes?'; expected_fact_ids=@('approval-remove-guest-001','approval-noisy-003') },
    [ordered]@{ id='eval-noisy-triage-001'; lab='core-3'; prompt='Summarize the highest severity incident and cite the supporting evidence.'; expected_fact_ids=@('incident-impossible-travel-001','evidence-signin-001','evidence-note-001') }
)

$collections = @{
    'users.json' = $users
    'groups.json' = $groups
    'roles.json' = $roles
    'access_reviews.json' = $accessReviews
    'incidents.json' = $incidents
    'approvals.json' = $approvals
    'evidence.json' = $evidence
}

foreach ($entry in $collections.GetEnumerator()) {
    $path = Join-Path $outputRoot $entry.Key
    $entry.Value | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding utf8
}

$evalRoot = Join-Path $PSScriptRoot 'datasets\eval'
if (-not (Test-Path $evalRoot)) {
    New-Item -ItemType Directory -Path $evalRoot | Out-Null
}
$eval | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $evalRoot 'noisy_eval.json') -Encoding utf8

Write-Output "Noisy seed pack generated at $outputRoot"